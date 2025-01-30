const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const db = require('./db');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// In-memory store for active tokens: Map token -> userId
const activeTokens = new Map();

// Utility: generate a random token
function generateToken() {
  return crypto.randomBytes(24).toString('hex');
}

// File upload endpoint
app.post('/upload', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  res.json({
    imageUrl: `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`
  });
});

// Register endpoint
app.post('/register', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;
    if (!email || !password || !displayName) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if user already exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (row) {
        return res.status(400).json({ error: 'Email already registered' });
      }

      // Hash the password
      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      // Insert new user
      db.run(
        `INSERT INTO users (email, passwordHash, displayName) VALUES (?, ?, ?)`,
        [email, passwordHash, displayName],
        function (err) {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database insert error' });
          }
          return res.json({ success: true, userId: this.lastID });
        }
      );
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Hardcoded admin credentials (store these in environment variables later!)
  const ADMIN_USER = "your_admin_username";
  const ADMIN_PASS = "your_admin_password";

  // Check for admin login first
  if (email === ADMIN_USER && password === ADMIN_PASS) {
    const token = generateToken();
    activeTokens.set(token, -1); // Special ID for admin
    return res.json({
      success: true,
      token,
      isModerator: true
    });
  }

  // Regular user login
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Compare password
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Generate a token, store it in memory
    const token = generateToken();
    activeTokens.set(token, user.id);

    return res.json({
      token,
      userId: user.id,
      displayName: user.displayName,
      isModerator: user.isModerator === 1
    });
  });
});

// Socket.IO setup
const io = socketIO(server, {
  cors: {
    origin: "*", // Or specify your Squarespace domain
    methods: ["GET", "POST"]
  }
});

// Socket.IO event handling
io.on('connection', (socket) => {
  console.log('New client connected');

  // Authentication middleware
  socket.on('authenticate', (data) => {
    const { token } = data;
    if (!token || !activeTokens.has(token)) {
      socket.emit('auth_error', { message: 'Invalid token' });
      socket.disconnect(true);
      return;
    }
    const userId = activeTokens.get(token);
    socket.userId = userId;

    // Load chat history
    db.all(`
      SELECT m.id AS messageId, m.text, m.imageUrl, m.timestamp, u.displayName
      FROM messages m
      JOIN users u ON m.userId = u.id
      ORDER BY m.id ASC
    `, (err, rows) => {
      if (err) {
        console.error(err);
        return;
      }
      socket.emit('chat_history', rows);
    });
  });

  // Handle text messages
  socket.on('new_text_message', (data) => {
    if (!socket.userId) return; // User not authenticated
    const { text, displayName } = data;
    const timestamp = new Date().toISOString();

    db.run(
      `INSERT INTO messages (userId, text, timestamp) VALUES (?, ?, ?)`,
      [socket.userId, text, timestamp],
      function (err) {
        if (err) {
          console.error(err);
          return;
        }
        const newMsg = {
          id: this.lastID,
          text,
          timestamp,
          displayName
        };
        io.emit('chat_message', newMsg);
      }
    );
  });

  // Handle image messages
  socket.on('new_image_message', (data) => {
    if (!socket.userId) return; // User not authenticated
    const { imageUrl, displayName } = data;
    const timestamp = new Date().toISOString();

    db.run(
      `INSERT INTO messages (userId, imageUrl, timestamp) VALUES (?, ?, ?)`,
      [socket.userId, imageUrl, timestamp],
      function (err) {
        if (err) {
          console.error(err);
          return;
        }
        const newMsg = {
          id: this.lastID,
          imageUrl,
          timestamp,
          displayName
        };
        io.emit('chat_message', newMsg);
      }
    );
  });

  // Handle message deletion
  socket.on('delete_message', (data) => {
    if (!socket.userId) return;
    const { messageId } = data;

    // Check if user is moderator
    db.get(`SELECT isModerator FROM users WHERE id = ?`, [socket.userId], (err, row) => {
      if (err || !row) return;
      if (row.isModerator === 1) {
        // User is moderator -> delete message
        db.run('DELETE FROM messages WHERE id = ?', [messageId], (delErr) => {
          if (delErr) {
            console.error(delErr);
            return;
          }
          io.emit('message_deleted', { messageId });
        });
      }
    });
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Start the server
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Chat server running on port ${PORT}`);
});