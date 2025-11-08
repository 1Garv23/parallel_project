// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const { promisify } = require('util');
require('dotenv').config();

const execPromise = promisify(exec);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const TEMP_DIR = path.join(__dirname, 'temp');

// Middleware
app.use(cors());
app.use(express.json());

// In-memory file storage (per user)
const fileStorage = new Map(); // userId -> [files]

// Ensure temp directory exists
(async () => {
  try {
    await fs.mkdir(TEMP_DIR, { recursive: true });
  } catch (err) {
    console.error('Error creating temp directory:', err);
  }
})();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://anshul:anshul@cluster0.fwu2qpu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Multer configuration for file uploads
const upload = multer({ dest: TEMP_DIR });

// Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Helper function to run pipeline commands
const runPipeline = async (inputPath, outputPath, isReverse = false) => {
  const command = isReverse 
    ? `./reverse_pipeline "${inputPath}" "${outputPath}"`
    : `./pipeline "${inputPath}" "${outputPath}"`;
  
  try {
    const { stdout, stderr } = await execPromise(command);
    console.log('Pipeline output:', stdout);
    if (stderr) console.error('Pipeline stderr:', stderr);
    return true;
  } catch (err) {
    console.error('Pipeline error:', err);
    throw new Error(`Pipeline execution failed: ${err.message}`);
  }
};

// Routes

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();

    // Initialize empty file list for user
    fileStorage.set(user._id.toString(), []);

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      token,
      user: { id: user._id, email: user.email }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Initialize file list if not exists
    if (!fileStorage.has(user._id.toString())) {
      fileStorage.set(user._id.toString(), []);
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user._id, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/user', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: { id: user._id, email: user.email } });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Upload and encrypt file
app.post('/api/upload', authenticate, upload.single('file'), async (req, res) => {
  let tempInputPath = null;
  let tempOutputPath = null;

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const userId = req.userId;
    tempInputPath = req.file.path;
    const fileId = Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9);
    tempOutputPath = path.join(TEMP_DIR, `${fileId}.enc`);

    // Run pipeline to compress and encrypt
    await runPipeline(tempInputPath, tempOutputPath, false);

    // Read encrypted file into memory
    const encryptedData = await fs.readFile(tempOutputPath);

    // Store file metadata and encrypted data in memory
    const fileMetadata = {
      id: fileId,
      originalName: req.file.originalname,
      size: req.file.size,
      encryptedData: encryptedData,
      uploadedAt: new Date().toISOString()
    };

    if (!fileStorage.has(userId)) {
      fileStorage.set(userId, []);
    }
    fileStorage.get(userId).push(fileMetadata);

    // Clean up temp files
    await fs.unlink(tempInputPath).catch(err => console.error('Error deleting temp input:', err));
    await fs.unlink(tempOutputPath).catch(err => console.error('Error deleting temp output:', err));

    res.json({
      message: 'File uploaded and encrypted successfully',
      file: {
        id: fileMetadata.id,
        originalName: fileMetadata.originalName,
        size: fileMetadata.size,
        uploadedAt: fileMetadata.uploadedAt
      }
    });
  } catch (err) {
    console.error('Upload error:', err);
    
    // Clean up on error
    if (tempInputPath) {
      await fs.unlink(tempInputPath).catch(() => {});
    }
    if (tempOutputPath) {
      await fs.unlink(tempOutputPath).catch(() => {});
    }

    res.status(500).json({ error: 'File upload failed: ' + err.message });
  }
});

// Get list of user's files
app.get('/api/files', authenticate, (req, res) => {
  try {
    const userId = req.userId;
    const userFiles = fileStorage.get(userId) || [];
    
    const fileList = userFiles.map(f => ({
      id: f.id,
      originalName: f.originalName,
      size: f.size,
      uploadedAt: f.uploadedAt
    }));

    res.json({ files: fileList });
  } catch (err) {
    console.error('Get files error:', err);
    res.status(500).json({ error: 'Failed to get files' });
  }
});

// Download encrypted file
app.get('/api/download/encrypted/:fileId', authenticate, async (req, res) => {
  try {
    const userId = req.userId;
    const fileId = req.params.fileId;
    
    const userFiles = fileStorage.get(userId) || [];
    const file = userFiles.find(f => f.id === fileId);

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}.enc"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(file.encryptedData);
  } catch (err) {
    console.error('Download encrypted error:', err);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Download original (decrypted and decompressed) file
app.get('/api/download/original/:fileId', authenticate, async (req, res) => {
  let tempEncryptedPath = null;
  let tempDecryptedPath = null;

  try {
    const userId = req.userId;
    const fileId = req.params.fileId;
    
    const userFiles = fileStorage.get(userId) || [];
    const file = userFiles.find(f => f.id === fileId);

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Write encrypted data to temp file
    tempEncryptedPath = path.join(TEMP_DIR, `${fileId}-temp.enc`);
    tempDecryptedPath = path.join(TEMP_DIR, `${fileId}-restored`);

    await fs.writeFile(tempEncryptedPath, file.encryptedData);

    // Run reverse pipeline to decrypt and decompress
    await runPipeline(tempEncryptedPath, tempDecryptedPath, true);

    // Read and send decrypted file
    const decryptedData = await fs.readFile(tempDecryptedPath);

    res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(decryptedData);

    // Clean up temp files
    await fs.unlink(tempEncryptedPath).catch(err => console.error('Error deleting temp encrypted:', err));
    await fs.unlink(tempDecryptedPath).catch(err => console.error('Error deleting temp decrypted:', err));
  } catch (err) {
    console.error('Download original error:', err);
    
    // Clean up on error
    if (tempEncryptedPath) {
      await fs.unlink(tempEncryptedPath).catch(() => {});
    }
    if (tempDecryptedPath) {
      await fs.unlink(tempDecryptedPath).catch(() => {});
    }

    res.status(500).json({ error: 'Download failed: ' + err.message });
  }
});

// Delete file
app.delete('/api/files/:fileId', authenticate, (req, res) => {
  try {
    const userId = req.userId;
    const fileId = req.params.fileId;
    
    const userFiles = fileStorage.get(userId) || [];
    const fileIndex = userFiles.findIndex(f => f.id === fileId);

    if (fileIndex === -1) {
      return res.status(404).json({ error: 'File not found' });
    }

    userFiles.splice(fileIndex, 1);
    fileStorage.set(userId, userFiles);

    res.json({ message: 'File deleted successfully' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Make sure ./pipeline and ./reverse_pipeline executables are in the same directory`);
});