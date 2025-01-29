// server.js
const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const db = require('./db');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

app.use(express.json());

/**
 * In-memory store for active tokens: Map token -> userId
 */
const activeTokens = new Map();

/**
 * Utility: generate a random token
 */
function generateToken() {
  return crypto.randomBytes(24).toString('hex');
}

/**
 * POST /register
 * Body: { email, password, displayName }
 */
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

/**
 * POST /login
 * Body: { email, password }
 * Returns: { token, userId, displayName, isModerator }
 */
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing email or password' });
  }

  // Find user by email
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

/**
 * Socket.IO handling
 */
io.on('connection', (socket) => {
  console.log('New client connected');

  // When the client sends 'authenticate', it includes { token }
  socket.on('authenticate', (data) => {
    const { token } = data;
    if (!token || !activeTokens.has(token)) {
      socket.emit('auth_error', { message: 'Invalid token' });
      socket.disconnect(true);
      return;
    }
    const userId = activeTokens.get(token);
    socket.userId = userId;

    // Send chat history
    db.all(`
      SELECT m.id AS messageId, m.text, m.timestamp, u.displayName
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

  // new_message
  socket.on('new_message', (data) => {
    if (!socket.userId) {
      return; // user not authenticated
    }
    const text = data.text || '';
    const timestamp = new Date().toISOString();

    db.run(
      `INSERT INTO messages (userId, text, timestamp) VALUES (?, ?, ?)`,
      [socket.userId, text, timestamp],
      function (err) {
        if (err) {
          console.error(err);
          return;
        }
        const messageId = this.lastID;
        // Grab user displayName to broadcast
        db.get(`SELECT displayName FROM users WHERE id = ?`, [socket.userId], (err, row) => {
          if (err) {
            console.error(err);
            return;
          }
          const newMsg = {
            messageId,
            text,
            timestamp,
            displayName: row.displayName
          };
          io.emit('chat_message', newMsg);
        });
      }
    );
  });

  // delete_message
  socket.on('delete_message', (data) => {
    if (!socket.userId) return;
    const { messageId } = data;

    // Check if user is moderator
    db.get(`SELECT isModerator FROM users WHERE id = ?`, [socket.userId], (err, row) => {
      if (err || !row) return;
      if (row.isModerator === 1) {
        // user is moderator -> delete message
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

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`Chat server running on port ${PORT}`);
});
