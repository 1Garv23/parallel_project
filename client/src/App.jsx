import React, { useState, useEffect } from 'react';
import { Upload, Download, Trash2, Lock, Unlock, FileText, LogOut } from 'lucide-react';
import './App.css'; 

const API_URL = 'http://localhost:3000/api';

function App() {
  const [user, setUser] = useState(null);
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [files, setFiles] = useState([]);
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      fetchUserData(token);
    }
  }, []);

  const fetchUserData = async (token) => {
    try {
      const res = await fetch(`${API_URL}/user`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        fetchFiles(token);
      } else {
        localStorage.removeItem('token');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchFiles = async (token) => {
    try {
      const res = await fetch(`${API_URL}/files`, {
        headers: { 'Authorization': `Bearer ${token || localStorage.getItem('token')}` }
      });
      if (res.ok) {
        const data = await res.json();
        setFiles(data.files);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const endpoint = isLogin ? '/login' : '/register';
      const res = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (res.ok) {
        localStorage.setItem('token', data.token);
        setUser(data.user);
        setEmail('');
        setPassword('');
        fetchFiles(data.token);
        setMessage(isLogin ? 'Login successful!' : 'Registration successful!');
      } else {
        setMessage(data.error || 'Authentication failed');
      }
    } catch (err) {
      setMessage('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setMessage('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_URL}/upload`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
        body: formData
      });

      const data = await res.json();

      if (res.ok) {
        setMessage('File uploaded and encrypted successfully!');
        fetchFiles();
      } else {
        setMessage(data.error || 'Upload failed');
      }
    } catch (err) {
      setMessage('Upload error. Please try again.');
    } finally {
      setLoading(false);
      e.target.value = '';
    }
  };

  const handleDownload = async (fileId, encrypted = false) => {
    setLoading(true);
    setMessage('');

    try {
      const endpoint = encrypted ? '/download/encrypted' : '/download/original';
      const res = await fetch(`${API_URL}${endpoint}/${fileId}`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });

      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = res.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || 'download';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        setMessage(`File downloaded successfully!`);
      } else {
        const data = await res.json();
        setMessage(data.error || 'Download failed');
      }
    } catch (err) {
      setMessage('Download error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (fileId) => {
    if (!confirm('Are you sure you want to delete this file?')) return;

    setLoading(true);
    setMessage('');

    try {
      const res = await fetch(`${API_URL}/files/${fileId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });

      const data = await res.json();

      if (res.ok) {
        setMessage('File deleted successfully!');
        fetchFiles();
      } else {
        setMessage(data.error || 'Delete failed');
      }
    } catch (err) {
      setMessage('Delete error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setUser(null);
    setFiles([]);
    setMessage('Logged out successfully');
  };

  if (!user) {
    return (
      <div className="auth-container">
        <div className="auth-box">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '1rem' }}>
            <Lock size={48} color="#6366f1" />
          </div>
          <h1 className="auth-title">Secure File Pipeline</h1>
          <p className="auth-subtitle">{isLogin ? 'Login to your account' : 'Create a new account'}</p>

          <form onSubmit={handleAuth} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <label>Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            <div>
              <label>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
            >
              {loading ? 'Processing...' : (isLogin ? 'Login' : 'Register')}
            </button>
          </form>

          <div style={{ marginTop: '1rem', textAlign: 'center' }}>
            <button
              onClick={() => {
                setIsLogin(!isLogin);
                setMessage('');
              }}
              className="auth-toggle"
            >
              {isLogin ? "Don't have an account? Register" : 'Already have an account? Login'}
            </button>
          </div>

          {message && (
            <div className={`message ${message.toLowerCase().includes('success') ? 'success' : 'error'}`}>
              {message}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <div className="container">
        <div className="card" style={{ marginBottom: '1rem' }}>
          <div className="dashboard-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <Lock size={32} color="#6366f1" />
              <div>
                <h1 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700, color: '#1f2937' }}>File Pipeline Dashboard</h1>
                <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280' }}>{user.email}</p>
              </div>
            </div>
            <button onClick={handleLogout} className="logout-btn" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <LogOut size={16} color="#fff" />
              <span>Logout</span>
            </button>
          </div>
        </div>

        <div className="card">
          <h2 style={{ marginTop: 0 }}>Upload File</h2>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <label className="upload-area" style={{ width: '100%' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', paddingTop: '1rem', paddingBottom: '1rem' }}>
                <Upload size={40} color="#9ca3af" style={{ marginBottom: '0.5rem' }} />
                <p style={{ margin: 0, fontSize: '0.9rem', color: '#6b7280' }}>Click to upload or drag and drop</p>
              </div>
              <input
                type="file"
                style={{ display: 'none' }}
                onChange={handleFileUpload}
                disabled={loading}
              />
            </label>
          </div>
        </div>

        {message && (
          <div className={`message ${message.toLowerCase().includes('success') ? 'success' : 'error'}`} style={{ marginTop: '1rem' }}>
            {message}
          </div>
        )}

        <div className="card">
          <h2 style={{ marginTop: 0 }}>Your Files</h2>

          {files.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem 0', color: '#6b7280' }}>
              <FileText size={64} color="#d1d5db" />
              <p>No files uploaded yet</p>
            </div>
          ) : (
            <div>
              {files.map((file) => (
                <div key={file.id} className="file-item">
                  <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                    <FileText size={28} color="#4f46e5" />
                    <div className="file-info">
                      <p style={{ margin: 0, fontWeight: 600, color: '#1f2937' }}>{file.originalName}</p>
                      <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280' }}>
                        Size: {(file.size / 1024).toFixed(2)} KB • Uploaded: {new Date(file.uploadedAt).toLocaleString()}
                      </p>
                    </div>
                  </div>

                  <div className="file-buttons">
                    <button
                      onClick={() => handleDownload(file.id, true)}
                      disabled={loading}
                      className="btn-yellow"
                      title="Download encrypted file"
                    >
                      <Lock size={14} color="#fff" style={{ marginRight: '6px' }} />
                      <span style={{ marginLeft: '4px' }}>Encrypted</span>
                    </button>

                    <button
                      onClick={() => handleDownload(file.id, false)}
                      disabled={loading}
                      className="btn-green"
                      title="Download original file"
                    >
                      <Unlock size={14} color="#fff" style={{ marginRight: '6px' }} />
                      <span style={{ marginLeft: '4px' }}>Original</span>
                    </button>

                    <button
                      onClick={() => handleDelete(file.id)}
                      disabled={loading}
                      className="btn-red"
                      title="Delete file"
                    >
                      <Trash2 size={14} color="#fff" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
