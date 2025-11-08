#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <zlib.h>

// Configuration
const size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks
const int AES_KEY_SIZE = 256;
#undef AES_BLOCK_SIZE
constexpr int AES_BLOCK_SIZE = 16;

// Mutex for thread-safe console output
std::mutex cout_mutex;

// Thread-safe console output
void safe_print(const std::string& msg) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << msg << std::endl;
}

// Structure to hold chunk data
struct Chunk {
    size_t index;
    std::vector<unsigned char> data;
    std::vector<unsigned char> processed_data;
    size_t original_size;
    size_t processed_size;
};

// Read file into chunks
std::vector<Chunk> read_file_chunks(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }

    std::vector<Chunk> chunks;
    size_t index = 0;

    while (file) {
        Chunk chunk;
        chunk.index = index++;
        chunk.data.resize(CHUNK_SIZE);
        
        file.read(reinterpret_cast<char*>(chunk.data.data()), CHUNK_SIZE);
        size_t bytes_read = file.gcount();
        
        if (bytes_read > 0) {
            chunk.data.resize(bytes_read);
            chunk.original_size = bytes_read;
            chunks.push_back(chunk);
        }
    }

    file.close();
    safe_print("File read into " + std::to_string(chunks.size()) + " chunks");
    return chunks;
}

// Compress a single chunk using zlib
void compress_chunk(Chunk& chunk) {
    uLongf compressed_size = compressBound(chunk.original_size);
    chunk.processed_data.resize(compressed_size);

    int result = compress(
        chunk.processed_data.data(),
        &compressed_size,
        chunk.data.data(),
        chunk.original_size
    );

    if (result != Z_OK) {
        safe_print("Compression failed for chunk " + std::to_string(chunk.index));
        return;
    }

    chunk.processed_data.resize(compressed_size);
    chunk.processed_size = compressed_size;
    
    float ratio = (1.0f - (float)compressed_size / chunk.original_size) * 100;
    safe_print("Chunk " + std::to_string(chunk.index) + " compressed: " + 
               std::to_string(chunk.original_size) + " -> " + 
               std::to_string(compressed_size) + " bytes (" + 
               std::to_string(ratio) + "% reduction)");
}

// Parallel compression
void parallel_compress(std::vector<Chunk>& chunks, int num_threads) {
    safe_print("\n=== Starting Parallel Compression ===");
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    size_t chunks_per_thread = (chunks.size() + num_threads - 1) / num_threads;

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&chunks, t, chunks_per_thread]() {
            size_t start_idx = t * chunks_per_thread;
            size_t end_idx = std::min(start_idx + chunks_per_thread, chunks.size());

            for (size_t i = start_idx; i < end_idx; ++i) {
                compress_chunk(chunks[i]);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    safe_print("Compression completed in " + std::to_string(duration.count()) + " ms\n");
}

// Encrypt a single chunk using AES-256-CTR
void encrypt_chunk(Chunk& chunk, const unsigned char* key, const unsigned char* base_iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        safe_print("Failed to create cipher context for chunk " + std::to_string(chunk.index));
        return;
    }

    // Create unique IV for this chunk by combining base IV with chunk index
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, base_iv, AES_BLOCK_SIZE);
    
    // Add chunk index to IV to make it unique
    for (size_t i = 0; i < sizeof(size_t) && i < AES_BLOCK_SIZE; ++i) {
        iv[i] ^= ((chunk.index >> (i * 8)) & 0xFF);
    }

    // Prepare output buffer (encryption may add padding)
    std::vector<unsigned char> encrypted_data(chunk.processed_size + AES_BLOCK_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        safe_print("Encryption init failed for chunk " + std::to_string(chunk.index));
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Encrypt
    if (EVP_EncryptUpdate(ctx, encrypted_data.data(), &len, 
                          chunk.processed_data.data(), chunk.processed_size) != 1) {
        safe_print("Encryption failed for chunk " + std::to_string(chunk.index));
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len) != 1) {
        safe_print("Encryption finalization failed for chunk " + std::to_string(chunk.index));
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    encrypted_data.resize(ciphertext_len);
    chunk.processed_data = encrypted_data;
    chunk.processed_size = ciphertext_len;

    EVP_CIPHER_CTX_free(ctx);
    safe_print("Chunk " + std::to_string(chunk.index) + " encrypted: " + 
               std::to_string(ciphertext_len) + " bytes");
}

// Parallel encryption
void parallel_encrypt(std::vector<Chunk>& chunks, const unsigned char* key, 
                      const unsigned char* iv, int num_threads) {
    safe_print("\n=== Starting Parallel Encryption ===");
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    size_t chunks_per_thread = (chunks.size() + num_threads - 1) / num_threads;

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&chunks, key, iv, t, chunks_per_thread]() {
            size_t start_idx = t * chunks_per_thread;
            size_t end_idx = std::min(start_idx + chunks_per_thread, chunks.size());

            for (size_t i = start_idx; i < end_idx; ++i) {
                encrypt_chunk(chunks[i], key, iv);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    safe_print("Encryption completed in " + std::to_string(duration.count()) + " ms\n");
}

// Write processed chunks to output file
void write_output(const std::vector<Chunk>& chunks, const std::string& output_file,
                  const unsigned char* key, const unsigned char* iv) {
    std::ofstream out(output_file, std::ios::binary);
    if (!out.is_open()) {
        throw std::runtime_error("Cannot create output file: " + output_file);
    }

    // Write header: number of chunks, key, IV
    size_t num_chunks = chunks.size();
    out.write(reinterpret_cast<const char*>(&num_chunks), sizeof(num_chunks));
    out.write(reinterpret_cast<const char*>(key), AES_KEY_SIZE / 8);
    out.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);

    // Write each chunk with its metadata
    for (const auto& chunk : chunks) {
        out.write(reinterpret_cast<const char*>(&chunk.index), sizeof(chunk.index));
        out.write(reinterpret_cast<const char*>(&chunk.original_size), sizeof(chunk.original_size));
        out.write(reinterpret_cast<const char*>(&chunk.processed_size), sizeof(chunk.processed_size));
        out.write(reinterpret_cast<const char*>(chunk.processed_data.data()), chunk.processed_size);
    }

    out.close();
    safe_print("Output written to: " + output_file);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file> [num_threads]" << std::endl;
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];
    int num_threads = (argc > 3) ? std::atoi(argv[3]) : std::thread::hardware_concurrency();

    std::cout << "=== Multithreaded Pipeline for Encrypted and Compressed Cloud Storage ===" << std::endl;
    std::cout << "Input file: " << input_file << std::endl;
    std::cout << "Output file: " << output_file << std::endl;
    std::cout << "Number of threads: " << num_threads << std::endl;
    std::cout << "Chunk size: " << CHUNK_SIZE / 1024 << " KB" << std::endl << std::endl;

    try {
        // Generate random AES key and IV
        unsigned char key[AES_KEY_SIZE / 8];
        unsigned char iv[AES_BLOCK_SIZE];
        
        if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
            throw std::runtime_error("Failed to generate random key/IV");
        }

        auto total_start = std::chrono::high_resolution_clock::now();

        // Step 1: Read file into chunks
        std::vector<Chunk> chunks = read_file_chunks(input_file);

        // Step 2: Parallel compression
        parallel_compress(chunks, num_threads);

        // Step 3: Parallel encryption
        parallel_encrypt(chunks, key, iv, num_threads);

        // Step 4: Write output
        write_output(chunks, output_file, key, iv);

        auto total_end = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_start);

        std::cout << "\n=== Pipeline Completed ===" << std::endl;
        std::cout << "Total processing time: " << total_duration.count() << " ms" << std::endl;

        // Calculate total sizes
        size_t original_total = 0, compressed_total = 0;
        for (const auto& chunk : chunks) {
            original_total += chunk.original_size;
            compressed_total += chunk.processed_size;
        }

        float overall_ratio = (1.0f - (float)compressed_total / original_total) * 100;
        std::cout << "Original size: " << original_total / 1024 << " KB" << std::endl;
        std::cout << "Final size: " << compressed_total / 1024 << " KB" << std::endl;
        std::cout << "Overall compression: " << overall_ratio << "%" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}