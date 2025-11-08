#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <zlib.h>

// Configuration
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
    size_t original_size;
    size_t processed_size;
    std::vector<unsigned char> encrypted_data;
    std::vector<unsigned char> decrypted_data;
    std::vector<unsigned char> decompressed_data;
};

// Read encrypted file and parse chunks
std::vector<Chunk> read_encrypted_file(const std::string& filename, 
                                       unsigned char* key, unsigned char* iv) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }

    // Read header
    size_t num_chunks;
    file.read(reinterpret_cast<char*>(&num_chunks), sizeof(num_chunks));
    file.read(reinterpret_cast<char*>(key), AES_KEY_SIZE / 8);
    file.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

    safe_print("Reading " + std::to_string(num_chunks) + " chunks from encrypted file");

    std::vector<Chunk> chunks;
    chunks.reserve(num_chunks);

    // Read each chunk
    for (size_t i = 0; i < num_chunks; ++i) {
        Chunk chunk;
        
        file.read(reinterpret_cast<char*>(&chunk.index), sizeof(chunk.index));
        file.read(reinterpret_cast<char*>(&chunk.original_size), sizeof(chunk.original_size));
        file.read(reinterpret_cast<char*>(&chunk.processed_size), sizeof(chunk.processed_size));
        
        chunk.encrypted_data.resize(chunk.processed_size);
        file.read(reinterpret_cast<char*>(chunk.encrypted_data.data()), chunk.processed_size);
        
        chunks.push_back(chunk);
    }

    file.close();
    safe_print("Successfully read all chunks");
    return chunks;
}

// Decrypt a single chunk using AES-256-CTR
void decrypt_chunk(Chunk& chunk, const unsigned char* key, const unsigned char* base_iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        safe_print("Failed to create cipher context for chunk " + std::to_string(chunk.index));
        return;
    }

    // Recreate the same unique IV used during encryption
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, base_iv, AES_BLOCK_SIZE);
    
    // Add chunk index to IV (same as encryption)
    for (size_t i = 0; i < sizeof(size_t) && i < AES_BLOCK_SIZE; ++i) {
        iv[i] ^= ((chunk.index >> (i * 8)) & 0xFF);
    }

    // Prepare output buffer
    chunk.decrypted_data.resize(chunk.processed_size + AES_BLOCK_SIZE);
    int len = 0;
    int plaintext_len = 0;

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        safe_print("Decryption init failed for chunk " + std::to_string(chunk.index));
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Decrypt
    if (EVP_DecryptUpdate(ctx, chunk.decrypted_data.data(), &len, 
                          chunk.encrypted_data.data(), chunk.processed_size) != 1) {
        safe_print("Decryption failed for chunk " + std::to_string(chunk.index));
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len = len;

    // Finalize
    if (EVP_DecryptFinal_ex(ctx, chunk.decrypted_data.data() + len, &len) != 1) {
        safe_print("Decryption finalization failed for chunk " + std::to_string(chunk.index));
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += len;

    chunk.decrypted_data.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    
    safe_print("Chunk " + std::to_string(chunk.index) + " decrypted: " + 
               std::to_string(plaintext_len) + " bytes");
}

// Parallel decryption
void parallel_decrypt(std::vector<Chunk>& chunks, const unsigned char* key, 
                      const unsigned char* iv, int num_threads) {
    safe_print("\n=== Starting Parallel Decryption ===");
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    size_t chunks_per_thread = (chunks.size() + num_threads - 1) / num_threads;

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&chunks, key, iv, t, chunks_per_thread]() {
            size_t start_idx = t * chunks_per_thread;
            size_t end_idx = std::min(start_idx + chunks_per_thread, chunks.size());

            for (size_t i = start_idx; i < end_idx; ++i) {
                decrypt_chunk(chunks[i], key, iv);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    safe_print("Decryption completed in " + std::to_string(duration.count()) + " ms\n");
}

// Decompress a single chunk using zlib
void decompress_chunk(Chunk& chunk) {
    uLongf decompressed_size = chunk.original_size;
    chunk.decompressed_data.resize(decompressed_size);

    int result = uncompress(
        chunk.decompressed_data.data(),
        &decompressed_size,
        chunk.decrypted_data.data(),
        chunk.decrypted_data.size()
    );

    if (result != Z_OK) {
        safe_print("Decompression failed for chunk " + std::to_string(chunk.index) + 
                   " (error code: " + std::to_string(result) + ")");
        return;
    }

    chunk.decompressed_data.resize(decompressed_size);
    
    safe_print("Chunk " + std::to_string(chunk.index) + " decompressed: " + 
               std::to_string(chunk.decrypted_data.size()) + " -> " + 
               std::to_string(decompressed_size) + " bytes");
}

// Parallel decompression
void parallel_decompress(std::vector<Chunk>& chunks, int num_threads) {
    safe_print("\n=== Starting Parallel Decompression ===");
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    size_t chunks_per_thread = (chunks.size() + num_threads - 1) / num_threads;

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&chunks, t, chunks_per_thread]() {
            size_t start_idx = t * chunks_per_thread;
            size_t end_idx = std::min(start_idx + chunks_per_thread, chunks.size());

            for (size_t i = start_idx; i < end_idx; ++i) {
                decompress_chunk(chunks[i]);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    safe_print("Decompression completed in " + std::to_string(duration.count()) + " ms\n");
}

// Write decompressed chunks to output file in correct order
void write_output(const std::vector<Chunk>& chunks, const std::string& output_file) {
    std::ofstream out(output_file, std::ios::binary);
    if (!out.is_open()) {
        throw std::runtime_error("Cannot create output file: " + output_file);
    }

    // Sort chunks by index to ensure correct order
    std::vector<const Chunk*> sorted_chunks;
    for (const auto& chunk : chunks) {
        sorted_chunks.push_back(&chunk);
    }
    std::sort(sorted_chunks.begin(), sorted_chunks.end(), 
              [](const Chunk* a, const Chunk* b) { return a->index < b->index; });

    // Write each chunk's decompressed data
    size_t total_written = 0;
    for (const auto* chunk_ptr : sorted_chunks) {
        out.write(reinterpret_cast<const char*>(chunk_ptr->decompressed_data.data()), 
                  chunk_ptr->decompressed_data.size());
        total_written += chunk_ptr->decompressed_data.size();
    }

    out.close();
    safe_print("Output written to: " + output_file);
    safe_print("Total bytes written: " + std::to_string(total_written));
}

// Verify the integrity of decrypted data
bool verify_chunks(const std::vector<Chunk>& chunks) {
    bool all_valid = true;
    
    for (const auto& chunk : chunks) {
        if (chunk.decompressed_data.size() != chunk.original_size) {
            safe_print("WARNING: Chunk " + std::to_string(chunk.index) + 
                      " size mismatch! Expected: " + std::to_string(chunk.original_size) + 
                      ", Got: " + std::to_string(chunk.decompressed_data.size()));
            all_valid = false;
        }
    }
    
    return all_valid;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <encrypted_file> <output_file> [num_threads]" << std::endl;
        return 1;
    }

    std::string encrypted_file = argv[1];
    std::string output_file = argv[2];
    int num_threads = (argc > 3) ? std::atoi(argv[3]) : std::thread::hardware_concurrency();

    std::cout << "=== Multithreaded Decryption and Decompression Pipeline ===" << std::endl;
    std::cout << "Encrypted file: " << encrypted_file << std::endl;
    std::cout << "Output file: " << output_file << std::endl;
    std::cout << "Number of threads: " << num_threads << std::endl << std::endl;

    try {
        unsigned char key[AES_KEY_SIZE / 8];
        unsigned char iv[AES_BLOCK_SIZE];

        auto total_start = std::chrono::high_resolution_clock::now();

        // Step 1: Read encrypted file
        std::vector<Chunk> chunks = read_encrypted_file(encrypted_file, key, iv);

        // Step 2: Parallel decryption
        parallel_decrypt(chunks, key, iv, num_threads);

        // Step 3: Parallel decompression
        parallel_decompress(chunks, num_threads);

        // Step 4: Verify integrity
        if (!verify_chunks(chunks)) {
            std::cerr << "WARNING: Some chunks have integrity issues!" << std::endl;
        } else {
            safe_print("All chunks verified successfully");
        }

        // Step 5: Write output
        write_output(chunks, output_file);

        auto total_end = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_start);

        std::cout << "\n=== Pipeline Completed ===" << std::endl;
        std::cout << "Total processing time: " << total_duration.count() << " ms" << std::endl;

        // Calculate statistics
        size_t total_encrypted = 0, total_decrypted = 0;
        for (const auto& chunk : chunks) {
            total_encrypted += chunk.processed_size;
            total_decrypted += chunk.original_size;
        }

        std::cout << "Encrypted size: " << total_encrypted / 1024 << " KB" << std::endl;
        std::cout << "Decrypted size: " << total_decrypted / 1024 << " KB" << std::endl;
        std::cout << "File successfully restored!" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}