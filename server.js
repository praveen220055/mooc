// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');

// Import the JWT middleware functions
const { verifyToken, ensureRole } = require('./authMiddleware');

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper function for database queries
async function query(text, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    return res;
  } finally {
    client.release();
  }
}

/* ========== AUTH ROUTES ========== */

// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const userCheck = await query('SELECT * FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Username already exists.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [username, hashedPassword, role]);
    res.json({ success: true, message: 'Registration successful.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password, role, secret } = req.body;
  try {
    const result = await query('SELECT * FROM users WHERE username = $1 AND role = $2', [username, role]);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'User not found.' });
    }
    const user = result.rows[0];
    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
      return res.status(400).json({ success: false, message: 'Invalid password.' });
    }
    if (role === 'host' && secret !== process.env.HOST_SECRET) {
      return res.status(400).json({ success: false, message: 'Invalid secret code.' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/* ========== HOST ROUTES ========== */

// Get host dashboard data (used to populate dropdowns)
app.get('/host/dashboard', verifyToken, ensureRole('host'), async (req, res) => {
  try {
    // CHANGED HERE: selecting subject_name AS "name"
    const subjects = await query(`
      SELECT id, subject_name AS "name"
      FROM subjects
      WHERE host_id = $1
    `, [req.user.id]);
    
    res.json({ success: true, subjects: subjects.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Add a subject
app.post('/host/subject', verifyToken, ensureRole('host'), async (req, res) => {
  const { subjectName } = req.body;
  try {
    // CHANGED HERE: inserting into subject_name
    await query(`
      INSERT INTO subjects (host_id, subject_name)
      VALUES ($1, $2)
    `, [req.user.id, subjectName]);

    res.json({ success: true, message: 'Subject added successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Add a link to a subject
app.post('/host/subject/:subjectId/link', verifyToken, ensureRole('host'), async (req, res) => {
  let { subjectId } = req.params;
  subjectId = parseInt(subjectId, 10);
  const { title, url } = req.body;
  try {
    await query('INSERT INTO links (subject_id, title, url) VALUES ($1, $2, $3)', [subjectId, title, url]);
    res.json({ success: true, message: 'Link added successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// View student visits for a subject's links
app.get('/host/subject/:subjectId/visits', verifyToken, ensureRole('host'), async (req, res) => {
  const { subjectId } = req.params;
  try {
    const result = await query(`
      SELECT u.username AS "studentUsername", v.visit_time
      FROM visits v
      JOIN links l ON v.link_id = l.id
      JOIN users u ON v.student_id = u.id
      WHERE l.subject_id = $1
      ORDER BY v.visit_time DESC
    `, [subjectId]);
    res.json({ success: true, visits: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/* ========== STUDENT ROUTES ========== */

// Get all subjects and their links for student dashboard
app.get('/student/dashboard', verifyToken, ensureRole('student'), async (req, res) => {
  try {
    // CHANGED HERE: selecting subject_name AS "name"
    const subjectsResult = await query(`
      SELECT id, subject_name AS "name"
      FROM subjects
    `, []);
    
    const subjects = subjectsResult.rows;
    for (let subject of subjects) {
      const linksResult = await query('SELECT id, title, url FROM links WHERE subject_id = $1', [subject.id]);
      subject.links = linksResult.rows;
    }
    res.json({ success: true, subjects });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Record a student visit and return the link URL for redirection
app.get('/student/link/:linkId', verifyToken, ensureRole('student'), async (req, res) => {
  const { linkId } = req.params;
  try {
    await query('INSERT INTO visits (link_id, student_id) VALUES ($1, $2)', [linkId, req.user.id]);
    const result = await query('SELECT url FROM links WHERE id = $1', [linkId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Link not found.' });
    }
    res.json({ success: true, url: result.rows[0].url });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
