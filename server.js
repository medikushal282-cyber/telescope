require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');
const multer = require('multer');
const axios = require('axios');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const JSZip = require('jszip');

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8000;
const JWT_SECRET = 'llmapp_secret_key_change_this';
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const DB_FILE = path.join(__dirname, 'db.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const TRASH_DIR = path.join(__dirname, 'trash');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(TRASH_DIR)) fs.mkdirSync(TRASH_DIR);

const { prepareWebContextForPrompt, safeFetchUrl, extractCleanText, searchWeb, validateSafeUrl, isPrivateIp } = require('./web_access');

// Web access rate limiter (sliding window: max 30 requests per minute per user)
const webAccessRateLimits = new Map();
function checkWebRateLimit(userId) {
  const now = Date.now();
  const windowMs = 60000;
  const maxReqs = 30;
  const timestamps = (webAccessRateLimits.get(userId) || []).filter(t => now - t < windowMs);
  if (timestamps.length >= maxReqs) return false;
  timestamps.push(now);
  webAccessRateLimits.set(userId, timestamps);
  return true;
}

// Verified Groq free models with actual tested benchmark speeds on Groq LPU hardware
const GROQ_MODELS = [
  {
    id: 'openai/gpt-oss-120b',
    name: 'GPT-OSS 120B (OpenAI / Groq)',
    provider: 'groq',
    category: 'Reasoning & Flagship',
    context: 131072,
    contextDisplay: '131k',
    speed: 475,
    speedDisplay: '475 t/s',
    description: 'OpenAI 120B flagship reasoning model running on ultra-fast Groq LPUs'
  },
  {
    id: 'openai/gpt-oss-20b',
    name: 'GPT-OSS 20B (OpenAI / Groq)',
    provider: 'groq',
    category: 'Fast & Real-time',
    context: 131072,
    contextDisplay: '131k',
    speed: 826,
    speedDisplay: '826 t/s',
    description: 'Ultra-fast 20B reasoning model with rapid inference at ~826 tokens/sec'
  },
  {
    id: 'qwen/qwen3.8-27b',
    name: 'Qwen 3.8 27B (Alibaba / Groq)',
    provider: 'groq',
    category: 'Coding & Math',
    context: 131072,
    contextDisplay: '131k',
    speed: 494,
    speedDisplay: '494 t/s',
    description: 'High-efficiency conversational model with stellar coding and instruction following'
  },
  {
    id: 'qwen/qwen3.6-27b',
    name: 'Qwen 3.6 27B (Alibaba / Groq)',
    provider: 'groq',
    category: 'Reasoning & Flagship',
    context: 131072,
    contextDisplay: '131k',
    speed: 461,
    speedDisplay: '461 t/s',
    description: 'Alibaba Cloud Qwen 3.6 with deep step-by-step reasoning and analysis'
  },
  {
    id: 'groq/compound',
    name: 'Compound Architecture (Groq)',
    provider: 'groq',
    category: 'Reasoning & Flagship',
    context: 131072,
    contextDisplay: '131k',
    speed: 465,
    speedDisplay: '465 t/s',
    description: 'Groq compound multi-step reasoning architecture for complex inquiries'
  },
  {
    id: 'groq/compound-mini',
    name: 'Compound Mini (Groq)',
    provider: 'groq',
    category: 'Fast & Real-time',
    context: 131072,
    contextDisplay: '131k',
    speed: 416,
    speedDisplay: '416 t/s',
    description: 'Compact compound model optimized for quick answers and sub-second generation'
  },
  {
    id: 'allam-2-7b',
    name: 'Allam-2 7B (SDAIA / Groq)',
    provider: 'groq',
    category: 'Fast & Real-time',
    context: 4096,
    contextDisplay: '4k',
    speed: 1386,
    speedDisplay: '1,386 t/s',
    description: 'Record-shattering ~1,386 t/s lightweight multilingual model'
  },
  {
    id: 'openai/gpt-oss-safeguard-20b',
    name: 'GPT-OSS Safeguard 20B (OpenAI / Groq)',
    provider: 'groq',
    category: 'General & Chat',
    context: 131072,
    contextDisplay: '131k',
    speed: 1016,
    speedDisplay: '1,016 t/s',
    description: 'Fast safety-aligned conversational assistant running at 1,000+ t/s'
  }
];

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_'));
  }
});
const upload = multer({ storage });

// ─── Admin credentials (hardcoded) ───────────────────────────────────────────
const ADMIN = {
  username: 'Laddu',
  passwordHash: '$2b$10$YC3YuAh8I2bQB3KqXOIKe.LqS.tpCptRysFhosHcN3FbxvIwpvGJC'
};

// ─── In-memory session tracking (userId → [{sessionId, ip, userAgent, loginTime, lastActivity, username}]) ─
const activeSessions = new Map(); // userId → Map of sessionId => session
let sessionIdCounter = 0;

function createSession(userId, username, ip, userAgent) {
  const sessionId = `${userId}-${++sessionIdCounter}-${Date.now()}`;
  const session = {
    sessionId,
    ip: ip || 'unknown',
    userAgent: userAgent || 'Unknown Device',
    loginTime: new Date().toISOString(),
    lastActivity: new Date().toISOString(),
    username
  };
  if (!activeSessions.has(userId)) activeSessions.set(userId, new Map());
  activeSessions.get(userId).set(sessionId, session);
  return sessionId;
}

function removeSession(userId, sessionId) {
  if (activeSessions.has(userId)) {
    activeSessions.get(userId).delete(sessionId);
    if (activeSessions.get(userId).size === 0) activeSessions.delete(userId);
  }
}

function getMultiLoginUsers() {
  const result = [];
  for (const [userId, sessions] of activeSessions.entries()) {
    if (sessions.size > 1) {
      result.push({
        userId,
        username: [...sessions.values()][0].username,
        sessions: [...sessions.values()]
      });
    }
  }
  return result;
}

// ─── JSON "database" helpers ─────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const init = {
      users: [],
      chats: [],
      globalMessages: [],
      privateMessages: [],
      fileMetadata: {},
      trash: [],
      multiLoginAlerts: [],
      urgentSignals: [],
      gameInvites: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
  if (!db.globalMessages) db.globalMessages = [];
  if (!db.privateMessages) db.privateMessages = [];
  if (!db.urgentSignals) db.urgentSignals = [];
  if (!db.gameInvites) db.gameInvites = [];
  if (!db.fileMetadata) db.fileMetadata = {};
  if (!db.trash) db.trash = [];
  if (!db.multiLoginAlerts) db.multiLoginAlerts = [];
  return db;
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ─── Auth middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    
    if (req.user.role !== 'admin') {
      const db = loadDB();
      const user = db.users.find(u => u.id === req.user.id);
      if (user && user.frozen) {
        return res.status(403).json({ error: 'Your account has been frozen by the admin.', code: 'ACCOUNT_FROZEN' });
      }
      
      // Strict Session Enforcement (Single Device)
      if (user && !user.allowMultiLogin) {
        const userSessions = activeSessions.get(req.user.id);
        if (!userSessions || !userSessions.has(req.user.sessionId)) {
           return res.status(401).json({ error: 'Session invalidated because account was accessed elsewhere or logged out.' });
        }
      }
    }
    
    // Update active session last activity timestamp
    if (req.user.id && req.user.sessionId && activeSessions.has(req.user.id)) {
      const sess = activeSessions.get(req.user.id).get(req.user.sessionId);
      if (sess) sess.lastActivity = new Date().toISOString();
    }
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    if (user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── Auth routes ──────────────────────────────────────────────────────────────

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN.username) {
    const valid = await bcrypt.compare(password, ADMIN.passwordHash);
    if (valid) {
      const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, role: 'admin' });
    }
  }
  res.status(401).json({ error: 'Invalid admin credentials' });
});

// User signup (creates pending request)
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const db = loadDB();
  if (db.users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const hashed = await bcrypt.hash(password, 10);
  db.users.push({
    id: Date.now().toString(),
    username,
    password: hashed,
    status: 'pending', // pending | approved | rejected
    frozen: false,
    allowMultiLogin: false,
    createdAt: new Date().toISOString()
  });
  saveDB(db);
  res.json({ message: 'Signup request submitted. Wait for admin approval.' });
});

// User login — enforces strict single-device policy with 5-minute lockout
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.status === 'pending') return res.status(403).json({ error: 'Your account is pending approval.' });
  if (user.status === 'rejected') return res.status(403).json({ error: 'Your account was rejected.' });
  if (user.frozen) return res.status(403).json({ error: 'Your account has been frozen by the admin.', code: 'ACCOUNT_FROZEN' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'Unknown Browser/Device';
  const now = Date.now();

  // Check single-device rule if not explicitly approved by admin
  if (!user.allowMultiLogin) {
    const existingSessions = activeSessions.get(user.id);
    if (existingSessions && existingSessions.size > 0) {
      const sessionsArr = [...existingSessions.values()];
      const latestSession = sessionsArr.sort((a, b) => new Date(b.lastActivity || b.loginTime) - new Date(a.lastActivity || a.loginTime))[0];
      
      const lastActiveTime = new Date(latestSession.lastActivity || latestSession.loginTime).getTime();
      const elapsedMs = now - lastActiveTime;
      
      // Incremental penalty array: 30s, 1m, 2m, 3m, 4m, 5m
      const penalties = [30, 60, 120, 180, 240, 300];
      const penaltyIndex = user.multiLoginPenalty || 0;
      const currentCooldownSeconds = penalties[Math.min(penaltyIndex, penalties.length - 1)];
      const COOLDOWN_MS = currentCooldownSeconds * 1000;

      if (elapsedMs < COOLDOWN_MS) {
        // Increment penalty for next time
        user.multiLoginPenalty = Math.min(penaltyIndex + 1, penalties.length - 1);
        
        const remainingSec = Math.ceil((COOLDOWN_MS - elapsedMs) / 1000);
        const mins = Math.floor(remainingSec / 60);
        const secs = remainingSec % 60;

        // Log this blocked multi-login alert for the admin
        if (!db.multiLoginAlerts) db.multiLoginAlerts = [];
        db.multiLoginAlerts.unshift({
          id: Date.now().toString(),
          userId: user.id,
          username: user.username,
          attemptedIp: clientIp,
          existingIp: latestSession.ip,
          userAgent,
          attemptedAt: new Date().toISOString(),
          remainingSeconds: remainingSec
        });
        if (db.multiLoginAlerts.length > 100) db.multiLoginAlerts = db.multiLoginAlerts.slice(0, 100);
        saveDB(db);

        console.warn(`⛔ [Auth] Multi-login blocked for ${user.username} from ${clientIp} (${remainingSec}s cooldown left, penalty level: ${user.multiLoginPenalty})`);

        return res.status(403).json({
          error: `Account is currently in use. Please wait ${mins}m ${secs}s before taking over. (Wait time increases with repeated attempts)`,
          code: 'MULTI_DEVICE_BLOCKED',
          remainingSeconds: remainingSec
        });
      } else {
        // Time elapsed, they successfully take over.
        activeSessions.delete(user.id);
      }
    }
  }

  // Reset penalty on successful login
  if (user.multiLoginPenalty > 0) {
    user.multiLoginPenalty = 0;
    saveDB(db);
  }

  const sessionId = createSession(user.id, user.username, clientIp, userAgent);

  const token = jwt.sign(
    { id: user.id, username: user.username, role: 'user', sessionId },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ token, role: 'user', username: user.username, allowMultiLogin: !!user.allowMultiLogin });
});

// Logout — removes session
app.post('/api/logout', authMiddleware, (req, res) => {
  if (req.user.sessionId) {
    removeSession(req.user.id, req.user.sessionId);
  }
  res.json({ success: true });
});

// ─── Admin routes ─────────────────────────────────────────────────────────────

// Get system stats for Admin Dashboard
app.get('/api/admin/stats', adminMiddleware, (req, res) => {
  const db = loadDB();
  const totalUsers = db.users.length;
  const pendingUsers = db.users.filter(u => u.status === 'pending').length;
  const approvedUsers = db.users.filter(u => u.status === 'approved').length;
  const frozenUsers = db.users.filter(u => u.frozen).length;
  const multiAllowedUsers = db.users.filter(u => u.allowMultiLogin).length;
  
  let activeSessionCount = 0;
  for (const sessions of activeSessions.values()) {
    activeSessionCount += sessions.size;
  }

  const multiAlerts = db.multiLoginAlerts || [];
  const totalChats = db.chats.length;
  const uploadsDir = path.join(__dirname, 'uploads');
  const filesCount = fs.existsSync(uploadsDir) ? fs.readdirSync(uploadsDir).length : 0;
  const trashCount = (db.trash || []).length;

  res.json({
    totalUsers,
    pendingUsers,
    approvedUsers,
    frozenUsers,
    multiAllowedUsers,
    activeSessionCount,
    multiLoginAlertCount: multiAlerts.length,
    totalChats,
    filesCount,
    trashCount,
    uptime: process.uptime()
  });
});

// Get all users (with frozen and allowMultiLogin flags)
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const db = loadDB();
  const users = db.users.map(u => ({
    id: u.id,
    username: u.username,
    status: u.status,
    frozen: !!u.frozen,
    allowMultiLogin: !!u.allowMultiLogin,
    createdAt: u.createdAt,
    activeSessionCount: activeSessions.get(u.id) ? activeSessions.get(u.id).size : 0
  }));
  res.json(users);
});

// Approve user
app.post('/api/admin/users/:id/approve', adminMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.status = 'approved';
  saveDB(db);
  res.json({ message: 'User approved' });
});

// Reject user
app.post('/api/admin/users/:id/reject', adminMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.status = 'rejected';
  saveDB(db);
  res.json({ message: 'User rejected' });
});

// Toggle or set allow multi-login for a specific user
app.post('/api/admin/users/:id/allow-multi-login', adminMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.allowMultiLogin = req.body.allow !== undefined ? Boolean(req.body.allow) : !user.allowMultiLogin;
  saveDB(db);
  console.log(`🔓 Admin updated multi-login for ${user.username}: ${user.allowMultiLogin}`);
  res.json({
    success: true,
    allowMultiLogin: user.allowMultiLogin,
    message: `Multi-login ${user.allowMultiLogin ? 'ALLOWED' : 'RESTRICTED'} for user ${user.username}`
  });
});

// View user chats
app.get('/api/admin/users/:id/chats', adminMiddleware, (req, res) => {
  const db = loadDB();
  const chats = db.chats.filter(c => c.userId === req.params.id);
  res.json(chats);
});

// ─── Multi-login Session Management (Admin) ────────────────────────────────────

// Get all active sessions + flag multi-login users
app.get('/api/admin/sessions', adminMiddleware, (req, res) => {
  const db = loadDB();
  const allSessions = [];
  for (const [userId, sessions] of activeSessions.entries()) {
    const dbUser = db.users.find(u => u.id === userId);
    for (const session of sessions.values()) {
      allSessions.push({
        userId,
        username: session.username,
        sessionId: session.sessionId,
        ip: session.ip,
        userAgent: session.userAgent || 'Unknown Device',
        loginTime: session.loginTime,
        lastActivity: session.lastActivity || session.loginTime,
        frozen: dbUser ? !!dbUser.frozen : false,
        allowMultiLogin: dbUser ? !!dbUser.allowMultiLogin : false,
        isMulti: sessions.size > 1
      });
    }
  }
  const multiLoginUsers = getMultiLoginUsers().map(u => {
    const dbUser = db.users.find(x => x.id === u.userId);
    return {
      userId: u.userId,
      username: u.username,
      allowMultiLogin: dbUser ? !!dbUser.allowMultiLogin : false,
      sessionCount: u.sessions.length,
      sessions: u.sessions
    };
  });
  res.json({ sessions: allSessions, multiLoginUsers });
});

// Get multi-login security alerts
app.get('/api/admin/multi-login-alerts', adminMiddleware, (req, res) => {
  const db = loadDB();
  res.json(db.multiLoginAlerts || []);
});

// Clear multi-login alerts
app.post('/api/admin/multi-login-alerts/clear', adminMiddleware, (req, res) => {
  const db = loadDB();
  db.multiLoginAlerts = [];
  saveDB(db);
  res.json({ success: true, message: 'Alerts cleared' });
});

// Freeze user (block access)
app.post('/api/admin/users/:id/freeze', adminMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.frozen = true;
  // Terminate active sessions immediately
  if (activeSessions.has(req.params.id)) activeSessions.delete(req.params.id);
  saveDB(db);
  console.log(`🔒 Admin froze user: ${user.username} (${user.id})`);
  res.json({ message: `User ${user.username} frozen and sessions revoked` });
});

// Unfreeze user (restore access)
app.post('/api/admin/users/:id/unfreeze', adminMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.frozen = false;
  saveDB(db);
  console.log(`🔓 Admin unfroze user: ${user.username} (${user.id})`);
  res.json({ message: `User ${user.username} unfrozen` });
});

// Force-logout all sessions for a user (kick them out everywhere)
app.post('/api/admin/users/:id/logout-all', adminMiddleware, (req, res) => {
  const uid = req.params.id;
  if (activeSessions.has(uid)) {
    activeSessions.delete(uid);
  }
  const db = loadDB();
  const user = db.users.find(u => u.id === uid);
  console.log(`👢 Admin force-logged out all sessions for: ${user ? user.username : uid}`);
  res.json({ message: `All sessions for user ${user ? user.username : uid} terminated` });
});

// Remove user (also clears sessions)
app.delete('/api/admin/users/:id', adminMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  db.users = db.users.filter(u => u.id !== req.params.id);
  db.chats = db.chats.filter(c => c.userId !== req.params.id);
  activeSessions.delete(req.params.id);
  saveDB(db);
  res.json({ message: 'User removed' });
});

// Helper to check OpenRouter Key status
async function checkKeyStatus(key) {
  try {
    const response = await axios.get('https://openrouter.ai/api/v1/key', {
      headers: { 'Authorization': `Bearer ${key}` }
    });
    const data = response.data.data;
    const limit = data.limit;
    const usage = data.usage;
    let status = 'usable';
    let remaining = 'unlimited';

    if (limit !== null && limit !== undefined) {
      if (usage >= limit) {
        status = 'exhausted';
      }
      remaining = `$${(limit - usage).toFixed(4)} left`;
    }
    
    return {
      key,
      label: data.label || 'Unnamed Key',
      status,
      remaining,
      usage: `$${usage.toFixed(4)}`,
      limit: limit !== null ? `$${limit.toFixed(4)}` : 'unlimited'
    };
  } catch (err) {
    return {
      key,
      label: 'Invalid Key',
      status: 'invalid',
      remaining: 'N/A',
      usage: 'N/A',
      limit: 'N/A'
    };
  }
}

// Verify a user-provided API key across multiple providers
app.post('/api/keys/verify', authMiddleware, async (req, res) => {
  const { key, provider } = req.body;
  if (!key || !key.trim()) return res.status(400).json({ error: 'Key is required' });
  const trimmed = key.trim();

  // Auto-detect provider if not specified
  let targetProvider = provider;
  if (!targetProvider) {
    if (trimmed.startsWith('gsk_')) targetProvider = 'groq';
    else if (trimmed.startsWith('sk-or-')) targetProvider = 'openrouter';
    else if (trimmed.startsWith('sk-ant-')) targetProvider = 'anthropic';
    else if (trimmed.startsWith('AIza')) targetProvider = 'gemini';
    else if (trimmed.startsWith('sk-')) targetProvider = 'openai';
    else targetProvider = 'openrouter';
  }

  if (targetProvider === 'groq' || trimmed.startsWith('gsk_')) {
    try {
      const resp = await axios.get('https://api.groq.com/openai/v1/models', {
        headers: { Authorization: `Bearer ${trimmed}` },
        timeout: 8000
      });
      return res.json({
        success: true,
        provider: 'groq',
        message: '✓ Groq API Key verified & active!',
        modelCount: resp.data?.data?.length || 0
      });
    } catch (err) {
      return res.status(400).json({
        error: 'Invalid Groq API key: ' + (err.response?.data?.error?.message || err.message)
      });
    }
  }

  if (targetProvider === 'openai' && !trimmed.startsWith('sk-or-')) {
    try {
      const resp = await axios.get('https://api.openai.com/v1/models', {
        headers: { Authorization: `Bearer ${trimmed}` },
        timeout: 8000
      });
      return res.json({
        success: true,
        provider: 'openai',
        message: '✓ OpenAI API Key verified & active!'
      });
    } catch (err) {
      return res.status(400).json({
        error: 'Invalid OpenAI key: ' + (err.response?.data?.error?.message || err.message)
      });
    }
  }

  if (targetProvider === 'anthropic') {
    if (!trimmed.startsWith('sk-ant-') || trimmed.length < 20) {
      return res.status(400).json({ error: 'Invalid Anthropic key format (should start with sk-ant-)' });
    }
    return res.json({ success: true, provider: 'anthropic', message: '✓ Anthropic key format accepted' });
  }

  if (targetProvider === 'gemini') {
    if (!trimmed.startsWith('AIza') || trimmed.length < 20) {
      return res.status(400).json({ error: 'Invalid Google Gemini API key format (should start with AIza)' });
    }
    return res.json({ success: true, provider: 'gemini', message: '✓ Google Gemini key accepted' });
  }

  // Default: OpenRouter verification
  const statusInfo = await checkKeyStatus(trimmed);
  if (statusInfo.status !== 'usable') {
    return res.status(400).json({ error: `Key is not usable (Status: ${statusInfo.status})` });
  }
  res.json({
    success: true,
    provider: 'openrouter',
    message: `✓ OpenRouter key accepted (${statusInfo.remaining})`,
    details: statusInfo
  });
});

// Get keys for admin edit (with detailed status)
app.get('/api/admin/keys', adminMiddleware, async (req, res) => {
  const db = loadDB();
  const keys = db.openrouterKeys || [];
  const results = await Promise.all(keys.map(k => checkKeyStatus(k)));
  res.json({ keys: results });
});

// Add a single backup key
app.post('/api/admin/keys', adminMiddleware, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Key is required' });
  
  const db = loadDB();
  if (!db.openrouterKeys) db.openrouterKeys = [];
  if (db.openrouterKeys.includes(key)) {
    return res.status(400).json({ error: 'Key already exists in the pool' });
  }

  // Validate the key first
  const statusInfo = await checkKeyStatus(key);
  if (statusInfo.status === 'invalid') {
    return res.status(400).json({ error: 'Key is invalid (OpenRouter verification failed)' });
  }

  db.openrouterKeys.push(key);
  saveDB(db);
  res.json({ message: 'Key added successfully', key: statusInfo });
});

// Remove a backup key
app.delete('/api/admin/keys', adminMiddleware, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Key is required' });
  
  const db = loadDB();
  if (!db.openrouterKeys) db.openrouterKeys = [];
  db.openrouterKeys = db.openrouterKeys.filter(k => k !== key);
  saveDB(db);
  res.json({ message: 'Key removed successfully' });
});

// ─── Urgent Help Signal ──────────────────────────────────────────────────────

// Broadcast an urgent signal to all users
app.post('/api/urgent-signal', authMiddleware, (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message is required' });

  const db = loadDB();
  const signal = {
    id: Date.now().toString(),
    fromUsername: req.user.username,
    message: message.trim().substring(0, 500),
    timestamp: new Date().toISOString()
  };
  if (!db.urgentSignals) db.urgentSignals = [];
  db.urgentSignals.push(signal);

  // Also post a trace message in global chat
  db.globalMessages.push({
    id: (Date.now() + 1).toString(),
    userId: req.user.id,
    username: req.user.username,
    content: `🚨 URGENT HELP SIGNAL from ${req.user.username}: "${signal.message}"`,
    attachments: [],
    timestamp: new Date().toISOString()
  });

  saveDB(db);
  console.log(`🚨 URGENT SIGNAL from ${req.user.username}: ${signal.message}`);
  res.json({ success: true });
});

// Poll for recent urgent signals (last 60 seconds, excludes self)
app.get('/api/urgent-signal/latest', authMiddleware, (req, res) => {
  const db = loadDB();
  const signals = (db.urgentSignals || []).filter(s => {
    const age = Date.now() - new Date(s.timestamp).getTime();
    return age < 60000 && s.fromUsername !== req.user.username;
  });
  res.json({ signals });
});



app.post('/api/admin/nuclear-panik', adminMiddleware, (req, res) => {
  try {
    const panikCode = req.body.code;
    if (panikCode !== 'NUCLEAR_EXTINCTION_CONFIRMED') {
      return res.status(400).json({ error: 'Invalid code' });
    }

    console.log(`\n🔴🔴🔴 NUCLEAR PANIK BY: ${req.user.username} 🔴🔴🔴`);

    res.json({ success: true, message: 'SYSTEM ANNIHILATION INITIATED' });

    setTimeout(() => {
      executeNuclearDestruction();
    }, 200);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



// ─── Social Zone — Game Invite Routes ─────────────────────────────────────────

// Send a game invite to another user
app.post('/api/game/invite', authMiddleware, (req, res) => {
  const { toUserId, game = 'tictactoe' } = req.body;
  if (!toUserId) return res.status(400).json({ error: 'toUserId is required' });
  if (toUserId === req.user.id) return res.status(400).json({ error: 'Cannot invite yourself' });

  const db = loadDB();
  const toUser = db.users.find(u => u.id === toUserId);
  if (!toUser) return res.status(404).json({ error: 'User not found' });

  // Remove any existing pending invite between these two users for same game
  db.gameInvites = (db.gameInvites || []).filter(i =>
    !(i.fromId === req.user.id && i.toId === toUserId && i.game === game && i.status === 'pending')
  );

  const invite = {
    id: Date.now().toString(),
    fromId: req.user.id,
    fromUsername: req.user.username,
    toId: toUserId,
    toUsername: toUser.username,
    game,
    status: 'pending', // pending | accepted | rejected | expired
    createdAt: new Date().toISOString()
  };
  db.gameInvites.push(invite);
  saveDB(db);
  res.json({ success: true, invite });
});

// Poll for pending invites sent TO this user (within last 30 seconds)
app.get('/api/game/invites/pending', authMiddleware, (req, res) => {
  const db = loadDB();
  const now = Date.now();
  const invites = (db.gameInvites || []).filter(i =>
    i.toId === req.user.id &&
    i.status === 'pending' &&
    (now - new Date(i.createdAt).getTime()) < 30000
  );
  res.json({ invites });
});

// Respond to an invite (accept or reject)
app.post('/api/game/invite/:id/respond', authMiddleware, (req, res) => {
  const { response } = req.body; // 'accept' | 'reject'
  if (!['accept', 'reject'].includes(response)) return res.status(400).json({ error: 'Invalid response' });

  const db = loadDB();
  const invite = (db.gameInvites || []).find(i => i.id === req.params.id && i.toId === req.user.id);
  if (!invite) return res.status(404).json({ error: 'Invite not found' });

  invite.status = response === 'accept' ? 'accepted' : 'rejected';
  invite.respondedAt = new Date().toISOString();

  if (response === 'accept') {
    // Initialize a game state
    if (!db.activeGames) db.activeGames = [];
    const existing = db.activeGames.find(g =>
      ((g.player1 === invite.fromId && g.player2 === invite.toId) ||
       (g.player1 === invite.toId && g.player2 === invite.fromId)) &&
      g.game === invite.game && g.status === 'active'
    );
    if (!existing) {
      db.activeGames.push({
        id: `game-${Date.now()}`,
        game: invite.game,
        player1: invite.fromId,
        player1Username: invite.fromUsername,
        player2: invite.toId,
        player2Username: invite.toUsername,
        board: Array(9).fill(null), // Tic Tac Toe 3x3
        currentTurn: invite.fromId, // Inviter goes first (X)
        status: 'active', // active | finished
        winner: null,
        createdAt: new Date().toISOString()
      });
    }
  }

  saveDB(db);
  res.json({ success: true, status: invite.status });
});

// Check if an invite was accepted (inviter polls this)
app.get('/api/game/invite/:id/status', authMiddleware, (req, res) => {
  const db = loadDB();
  const invite = (db.gameInvites || []).find(i => i.id === req.params.id);
  if (!invite) return res.status(404).json({ error: 'Invite not found' });
  res.json({ status: invite.status });
});

// Get active game between this user and another
app.get('/api/game/active', authMiddleware, (req, res) => {
  const db = loadDB();
  if (!db.activeGames) return res.json({ game: null });
  const game = db.activeGames.find(g =>
    (g.player1 === req.user.id || g.player2 === req.user.id) && g.status === 'active'
  );
  res.json({ game: game || null });
});

// Make a move in Tic Tac Toe
app.post('/api/game/:id/move', authMiddleware, (req, res) => {
  const { cellIndex } = req.body;
  if (cellIndex === undefined || cellIndex < 0 || cellIndex > 8) return res.status(400).json({ error: 'Invalid cell' });

  const db = loadDB();
  if (!db.activeGames) return res.status(404).json({ error: 'Game not found' });
  const game = db.activeGames.find(g => g.id === req.params.id && g.status === 'active');
  if (!game) return res.status(404).json({ error: 'Game not found or finished' });
  if (game.currentTurn !== req.user.id) return res.status(400).json({ error: 'Not your turn' });
  if (game.board[cellIndex] !== null) return res.status(400).json({ error: 'Cell already taken' });

  const isPlayer1 = game.player1 === req.user.id;
  game.board[cellIndex] = isPlayer1 ? 'X' : 'O';

  // Check win
  const wins = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  const mark = game.board[cellIndex];
  const won = wins.some(([a,b,c]) => game.board[a] === mark && game.board[b] === mark && game.board[c] === mark);
  if (won) {
    game.status = 'finished';
    game.winner = req.user.id;
    game.winnerUsername = req.user.username;
  } else if (game.board.every(c => c !== null)) {
    game.status = 'finished';
    game.winner = 'draw';
  } else {
    game.currentTurn = isPlayer1 ? game.player2 : game.player1;
  }

  saveDB(db);
  res.json({ game });
});

// Resign / forfeit a game
app.post('/api/game/:id/resign', authMiddleware, (req, res) => {
  const db = loadDB();
  if (!db.activeGames) return res.status(404).json({ error: 'Game not found' });
  const game = db.activeGames.find(g => g.id === req.params.id && g.status === 'active');
  if (!game) return res.status(404).json({ error: 'Game not found' });
  game.status = 'finished';
  game.winner = req.user.id === game.player1 ? game.player2 : game.player1;
  game.winnerUsername = req.user.id === game.player1 ? game.player2Username : game.player1Username;
  game.resignedBy = req.user.id;
  saveDB(db);
  res.json({ game });
});



// Get users for PMs (excluding passwords)
app.get('/api/users', authMiddleware, (req, res) => {
  const db = loadDB();
  const users = db.users
    .filter(u => u.status === 'approved')
    .map(u => ({ id: u.id, username: u.username }));
  res.json(users);
});

// ─── Global Chat routes ────────────────────────────────────────────────────────
app.get('/api/chat/global', authMiddleware, (req, res) => {
  const db = loadDB();
  res.json(db.globalMessages);
});

app.post('/api/chat/global', authMiddleware, (req, res) => {
  const { message, attachments = [], replyTo = null } = req.body;
  if (!message && attachments.length === 0) return res.status(400).json({ error: 'Empty message' });
  const db = loadDB();
  const newMsg = {
    id: Date.now().toString(),
    userId: req.user.id,
    username: req.user.username,
    content: message,
    replyTo: replyTo,
    attachments: attachments,
    timestamp: new Date().toISOString()
  };
  db.globalMessages.push(newMsg);
  saveDB(db);
  res.json(newMsg);
});

app.delete('/api/chat/global', adminMiddleware, (req, res) => {
  const db = loadDB();
  db.globalMessages = [];
  saveDB(db);
  res.json({ message: 'Global chat cleared' });
});

// ─── Private Chat routes ───────────────────────────────────────────────────────
app.get('/api/chat/private/:userId', authMiddleware, (req, res) => {
  const db = loadDB();
  const myId = req.user.id;
  const otherId = req.params.userId;
  const pms = db.privateMessages.filter(m =>
    (m.from === myId && m.to === otherId) || (m.from === otherId && m.to === myId)
  );
  res.json(pms);
});

app.post('/api/chat/private/:userId', authMiddleware, (req, res) => {
  const { message, attachments = [], replyTo = null } = req.body;
  if (!message && attachments.length === 0) return res.status(400).json({ error: 'Empty message' });
  const db = loadDB();
  const otherId = req.params.userId;
  const newMsg = {
    id: Date.now().toString(),
    from: req.user.id,
    fromUsername: req.user.username,
    to: otherId,
    content: message,
    replyTo: replyTo,
    attachments: attachments,
    timestamp: new Date().toISOString()
  };
  db.privateMessages.push(newMsg);
  saveDB(db);
  res.json(newMsg);
});

// Get latest message updates (for notifications & badges)
app.get('/api/updates', authMiddleware, (req, res) => {
  const db = loadDB();
  const myId = req.user.id;
  
  // Last global message
  const lastGlobalMsg = db.globalMessages.length ? db.globalMessages[db.globalMessages.length - 1] : null;
  
  // Latest PMs per sender
  const pmUpdates = {};
  db.privateMessages.forEach(m => {
    if (m.to === myId) {
       if (!pmUpdates[m.from] || m.timestamp > pmUpdates[m.from].timestamp) {
           pmUpdates[m.from] = m;
       }
    }
  });

  res.json({
    global: lastGlobalMsg,
    pms: pmUpdates
  });
});

// ─── File Upload & Safety Trash Bin Routes ───────────────────────────────────

// Get active uploaded files with uploader metadata
app.get('/api/files', authMiddleware, (req, res) => {
  if (!fs.existsSync(UPLOADS_DIR)) {
    return res.json([]);
  }
  const db = loadDB();
  const metaMap = db.fileMetadata || {};

  fs.readdir(UPLOADS_DIR, (err, files) => {
    if (err) return res.status(500).json({ error: 'Failed to read directory' });
    const fileList = files.map(filename => {
      const filePath = path.join(UPLOADS_DIR, filename);
      const stats = fs.statSync(filePath);
      const meta = metaMap[filename] || {};
      return {
        id: filename,
        filename: filename,
        name: meta.name || filename.substring(filename.indexOf('-') + 1),
        size: meta.size || (stats.size / 1024).toFixed(1) + ' KB',
        url: `/uploads/${filename}`,
        uploadedBy: meta.uploadedBy || 'System / Prior User',
        uploaderId: meta.uploaderId || null,
        uploadedAt: meta.uploadedAt || stats.birthtime,
        createdAt: stats.birthtime
      };
    });
    // Sort newest first
    fileList.sort((a, b) => new Date(b.uploadedAt || b.createdAt) - new Date(a.uploadedAt || a.createdAt));
    res.json(fileList);
  });
});

// Upload new files and record uploader metadata
app.post('/api/upload', authMiddleware, upload.array('files'), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }
  const db = loadDB();
  if (!db.fileMetadata) db.fileMetadata = {};

  const uploadedFiles = req.files.map(f => {
    const fileInfo = {
      id: f.filename,
      filename: f.filename,
      name: f.originalname,
      size: (f.size / 1024).toFixed(1) + ' KB',
      uploadedBy: req.user.username,
      uploaderId: req.user.id,
      uploadedAt: new Date().toISOString()
    };
    db.fileMetadata[f.filename] = fileInfo;
    return f.filename;
  });

  saveDB(db);
  res.json({ message: 'Files uploaded successfully', count: req.files.length, files: uploadedFiles });
});

// Soft-delete a file: moves to trash folder instead of permanent unlinking
app.delete('/api/files/:filename', authMiddleware, (req, res) => {
  const filename = req.params.filename;
  const srcPath = path.join(UPLOADS_DIR, filename);
  const destPath = path.join(TRASH_DIR, filename);

  if (!fs.existsSync(srcPath)) {
    return res.status(404).json({ error: 'File not found in active uploads' });
  }

  try {
    fs.renameSync(srcPath, destPath);
    const db = loadDB();
    if (!db.trash) db.trash = [];
    const meta = db.fileMetadata?.[filename] || {};
    
    // Remove from existing trash if duplicate
    db.trash = db.trash.filter(t => t.filename !== filename);
    db.trash.unshift({
      id: filename,
      filename: filename,
      name: meta.name || filename.substring(filename.indexOf('-') + 1),
      size: meta.size || 'Unknown',
      uploadedBy: meta.uploadedBy || 'Unknown',
      uploadedAt: meta.uploadedAt || null,
      deletedBy: req.user.username,
      deletedById: req.user.id,
      deletedAt: new Date().toISOString()
    });
    saveDB(db);

    console.log(`🗑️ [Trash] Moved ${filename} to trash by ${req.user.username}`);
    res.json({ success: true, message: 'File moved to Trash Bin', filename });
  } catch (err) {
    console.error('Error soft-deleting file:', err);
    res.status(500).json({ error: 'Failed to move file to trash: ' + err.message });
  }
});

// Bulk soft-delete multiple files
app.post('/api/files/bulk-delete', authMiddleware, (req, res) => {
  const files = req.body.files || req.body.filenames;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'No files provided for deletion' });
  }

  const db = loadDB();
  if (!db.trash) db.trash = [];
  let movedCount = 0;

  for (const filename of files) {
    const srcPath = path.join(UPLOADS_DIR, filename);
    const destPath = path.join(TRASH_DIR, filename);
    if (fs.existsSync(srcPath)) {
      try {
        fs.renameSync(srcPath, destPath);
        const meta = db.fileMetadata?.[filename] || {};
        db.trash = db.trash.filter(t => t.filename !== filename);
        db.trash.unshift({
          id: filename,
          filename: filename,
          name: meta.name || filename.substring(filename.indexOf('-') + 1),
          size: meta.size || 'Unknown',
          uploadedBy: meta.uploadedBy || 'Unknown',
          uploadedAt: meta.uploadedAt || null,
          deletedBy: req.user.username,
          deletedById: req.user.id,
          deletedAt: new Date().toISOString()
        });
        movedCount++;
      } catch (e) {
        console.error(`Failed to move ${filename} to trash:`, e);
      }
    }
  }

  saveDB(db);
  res.json({ success: true, count: movedCount, message: `${movedCount} file(s) moved to Trash Bin` });
});

// Bulk download selected files as a ZIP archive
app.post('/api/files/bulk-download-zip', authMiddleware, async (req, res) => {
  const files = req.body.files || req.body.filenames;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'No files provided for ZIP bundle' });
  }

  const db = loadDB();
  const metaMap = db.fileMetadata || {};
  const zip = new JSZip();
  let addedCount = 0;

  for (const filename of files) {
    const filePath = path.join(UPLOADS_DIR, filename);
    if (fs.existsSync(filePath)) {
      const meta = metaMap[filename];
      const cleanName = (meta && meta.name) ? meta.name : filename.substring(filename.indexOf('-') + 1) || filename;
      try {
        const data = fs.readFileSync(filePath);
        zip.file(cleanName, data);
        addedCount++;
      } catch (e) {
        console.error(`Failed to read file ${filename} for zip:`, e);
      }
    }
  }

  if (addedCount === 0) {
    return res.status(404).json({ error: 'None of the requested files were found on disk' });
  }

  try {
    const zipBuffer = await zip.generateAsync({
      type: 'nodebuffer',
      compression: 'DEFLATE',
      compressionOptions: { level: 6 }
    });
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="telescope_files.zip"');
    res.send(zipBuffer);
  } catch (err) {
    console.error('Error generating zip:', err);
    res.status(500).json({ error: 'Failed to generate ZIP archive: ' + err.message });
  }
});

// Get all files in Trash Bin
app.get('/api/trash', authMiddleware, (req, res) => {
  if (!fs.existsSync(TRASH_DIR)) {
    return res.json([]);
  }
  const db = loadDB();
  const trashItems = (db.trash || []).filter(item => {
    const p = path.join(TRASH_DIR, item.filename);
    return fs.existsSync(p);
  });
  res.json(trashItems);
});

// Restore a file from Trash Bin back to active uploads
app.post('/api/trash/:filename/restore', authMiddleware, (req, res) => {
  const filename = req.params.filename;
  const srcPath = path.join(TRASH_DIR, filename);
  const destPath = path.join(UPLOADS_DIR, filename);

  if (!fs.existsSync(srcPath)) {
    return res.status(404).json({ error: 'File not found in Trash Bin' });
  }

  try {
    fs.renameSync(srcPath, destPath);
    const db = loadDB();
    if (db.trash) {
      db.trash = db.trash.filter(t => t.filename !== filename);
      saveDB(db);
    }
    console.log(`♻️ [Trash] Restored ${filename} by ${req.user.username}`);
    res.json({ success: true, message: 'File restored successfully', filename });
  } catch (err) {
    console.error('Error restoring file:', err);
    res.status(500).json({ error: 'Failed to restore file: ' + err.message });
  }
});

// Permanently delete a file from Trash Bin
app.delete('/api/trash/:filename', authMiddleware, (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(TRASH_DIR, filename);

  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
    } catch (e) {
      console.error('Failed to unlink from trash:', e);
    }
  }

  const db = loadDB();
  if (db.trash) {
    db.trash = db.trash.filter(t => t.filename !== filename);
  }
  if (db.fileMetadata && db.fileMetadata[filename]) {
    delete db.fileMetadata[filename];
  }
  saveDB(db);

  res.json({ success: true, message: 'File permanently deleted' });
});

// Empty entire Trash Bin
app.delete('/api/trash', authMiddleware, (req, res) => {
  const db = loadDB();
  let deletedCount = 0;

  if (fs.existsSync(TRASH_DIR)) {
    const files = fs.readdirSync(TRASH_DIR);
    for (const f of files) {
      try {
        fs.unlinkSync(path.join(TRASH_DIR, f));
        deletedCount++;
      } catch (e) {}
    }
  }

  db.trash = [];
  saveDB(db);
  res.json({ success: true, count: deletedCount, message: `Trash Bin emptied (${deletedCount} files purged)` });
});

// Curated OpenRouter benchmark models with tested speed & metadata
const CURATED_OPENROUTER_MODELS = [
  {
    id: 'openai/gpt-4o',
    name: 'GPT-4o (OpenAI)',
    provider: 'openrouter',
    category: 'Reasoning & Flagship',
    context: 128000,
    contextDisplay: '128k',
    speed: 75,
    speedDisplay: '75 t/s',
    description: 'OpenAI flagship multimodal intelligence model'
  },
  {
    id: 'anthropic/claude-3.5-sonnet',
    name: 'Claude 3.5 Sonnet (Anthropic)',
    provider: 'openrouter',
    category: 'Reasoning & Flagship',
    context: 200000,
    contextDisplay: '200k',
    speed: 65,
    speedDisplay: '65 t/s',
    description: 'State-of-the-art coding, analysis and reasoning'
  },
  {
    id: 'google/gemini-1.5-pro',
    name: 'Gemini 1.5 Pro (Google)',
    provider: 'openrouter',
    category: 'Reasoning & Flagship',
    context: 2000000,
    contextDisplay: '2M',
    speed: 55,
    speedDisplay: '55 t/s',
    description: 'Massive 2-million token multimodal context window'
  },
  {
    id: 'google/gemini-1.5-flash',
    name: 'Gemini 1.5 Flash (Google)',
    provider: 'openrouter',
    category: 'Fast & Real-time',
    context: 1000000,
    contextDisplay: '1M',
    speed: 120,
    speedDisplay: '120 t/s',
    description: 'Ultra-fast 1M context multimodal reasoning'
  },
  {
    id: 'deepseek/deepseek-chat',
    name: 'DeepSeek V3 (DeepSeek)',
    provider: 'openrouter',
    category: 'Coding & Math',
    context: 64000,
    contextDisplay: '64k',
    speed: 60,
    speedDisplay: '60 t/s',
    description: 'Leading frontier open-weights model for general and coding'
  },
  {
    id: 'deepseek/deepseek-r1',
    name: 'DeepSeek R1 (DeepSeek)',
    provider: 'openrouter',
    category: 'Reasoning & Flagship',
    context: 64000,
    contextDisplay: '64k',
    speed: 35,
    speedDisplay: '35 t/s',
    description: 'Advanced reasoning and step-by-step thinking model'
  },
  {
    id: 'meta-llama/llama-3.1-405b-instruct',
    name: 'Llama 3.1 405B (Meta)',
    provider: 'openrouter',
    category: 'Reasoning & Flagship',
    context: 128000,
    contextDisplay: '128k',
    speed: 40,
    speedDisplay: '40 t/s',
    description: 'Meta flagship 405B parameter open-weights model'
  },
  {
    id: 'mistralai/mistral-large',
    name: 'Mistral Large (Mistral)',
    provider: 'openrouter',
    category: 'General & Chat',
    context: 128000,
    contextDisplay: '128k',
    speed: 50,
    speedDisplay: '50 t/s',
    description: 'Top-tier multilingual European frontier model'
  },
  {
    id: 'qwen/qwen-2.5-72b-instruct',
    name: 'Qwen 2.5 72B (Alibaba)',
    provider: 'openrouter',
    category: 'Coding & Math',
    context: 128000,
    contextDisplay: '128k',
    speed: 45,
    speedDisplay: '45 t/s',
    description: 'High-accuracy math, code and multi-turn instruction'
  }
];

const LOCAL_OLLAMA_MODEL = {
  id: 'llama3.2',
  name: 'Llama 3.2 (Local Ollama)',
  provider: 'ollama',
  category: 'Local',
  context: 8192,
  contextDisplay: '8k',
  speed: 25,
  speedDisplay: '25 t/s',
  description: 'Private offline local inference via Ollama'
};

// Get available models (Verified models: Groq LPU + Curated OpenRouter Flagship + Local Ollama)
app.get('/api/models', async (req, res) => {
  try {
    const verifiedModels = [
      ...GROQ_MODELS,
      ...CURATED_OPENROUTER_MODELS,
      LOCAL_OLLAMA_MODEL
    ];

    res.json({
      models: verifiedModels,
      defaultModel: 'openai/gpt-oss-120b'
    });
  } catch (err) {
    console.error('Error in /api/models:', err.message);
    res.json({
      models: [...GROQ_MODELS, ...CURATED_OPENROUTER_MODELS, LOCAL_OLLAMA_MODEL],
      defaultModel: 'openai/gpt-oss-120b'
    });
  }
});

// Get all chats for user
app.get('/api/chats', authMiddleware, (req, res) => {
  const db = loadDB();
  const chats = db.chats
    .filter(c => c.userId === req.user.id)
    .map(c => ({ id: c.id, title: c.title, createdAt: c.createdAt, updatedAt: c.updatedAt }))
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  res.json(chats);
});

// Create new chat
app.post('/api/chats', authMiddleware, (req, res) => {
  const db = loadDB();
  const chat = {
    id: Date.now().toString(),
    userId: req.user.id,
    title: 'New Chat',
    messages: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  db.chats.push(chat);
  saveDB(db);
  res.json(chat);
});

// Get single chat
app.get('/api/chats/:id', authMiddleware, (req, res) => {
  const db = loadDB();
  const chat = db.chats.find(c => c.id === req.params.id && c.userId === req.user.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  res.json(chat);
});

// Delete chat
app.delete('/api/chats/:id', authMiddleware, (req, res) => {
  const db = loadDB();
  db.chats = db.chats.filter(c => !(c.id === req.params.id && c.userId === req.user.id));
  saveDB(db);
  res.json({ message: 'Chat deleted' });
});

// Send message (with context memory + Ollama or OpenRouter or Groq + Web Access)
app.post('/api/chats/:id/message', authMiddleware, async (req, res) => {
  const {
    message,
    model = 'llama3.2',
    attachments = [],
    openrouterKey,
    groqKey,
    customKeys = {},
    noContext,
    webAccess
  } = req.body;

  const db = loadDB();
  const chat = db.chats.find(c => c.id === req.params.id && c.userId === req.user.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  let extractedText = '';
  let visionImages = [];

  if (attachments && attachments.length > 0) {
    for (const filename of attachments) {
      const filepath = path.join(__dirname, 'uploads', filename);
      if (!fs.existsSync(filepath)) continue;

      const ext = path.extname(filename).toLowerCase();

      if (['.jpg', '.jpeg', '.png', '.webp'].includes(ext)) {
        const base64 = fs.readFileSync(filepath).toString('base64');
        const mime = ext === '.png' ? 'image/png' : ext === '.webp' ? 'image/webp' : 'image/jpeg';
        visionImages.push(`data:${mime};base64,${base64}`);
        extractedText += `\n\n[Attached Image: ${filename}]`;
      } else if (ext === '.pdf') {
        try {
          const dataBuffer = fs.readFileSync(filepath);
          const data = await pdfParse(dataBuffer);
          extractedText += `\n\n--- Attached File: ${filename} ---\n${data.text}\n`;
        } catch (e) { console.error('PDF Parse Error:', e); }
      } else if (ext === '.docx') {
        try {
          const result = await mammoth.extractRawText({ path: filepath });
          extractedText += `\n\n--- Attached File: ${filename} ---\n${result.value}\n`;
        } catch (e) { console.error('DOCX Parse Error:', e); }
      } else if (ext === '.ipynb') {
        try {
          const raw = fs.readFileSync(filepath, 'utf8');
          const nb = JSON.parse(raw);
          let nbText = `Jupyter Notebook: ${filename}\n`;
          if (Array.isArray(nb.cells)) {
            nb.cells.forEach((cell, idx) => {
              const ctype = cell.cell_type || 'code';
              const src = Array.isArray(cell.source) ? cell.source.join('') : (cell.source || '');
              nbText += `\n[Cell ${idx + 1} - ${ctype.toUpperCase()}]:\n${src}\n`;
              if (cell.outputs && Array.isArray(cell.outputs)) {
                cell.outputs.forEach(out => {
                  if (out.text) {
                    const txt = Array.isArray(out.text) ? out.text.join('') : out.text;
                    nbText += `[Output]: ${txt}\n`;
                  } else if (out.data && out.data['text/plain']) {
                    const txt = Array.isArray(out.data['text/plain']) ? out.data['text/plain'].join('') : out.data['text/plain'];
                    nbText += `[Output]: ${txt}\n`;
                  }
                });
              }
            });
          }
          extractedText += `\n\n--- Attached Notebook: ${filename} ---\n${nbText.substring(0, 50000)}\n`;
        } catch (e) {
          console.error('IPYNB Parse Error:', e);
          try {
            const raw = fs.readFileSync(filepath, 'utf8');
            extractedText += `\n\n--- Attached File: ${filename} ---\n${raw.substring(0, 50000)}\n`;
          } catch(e2) {}
        }
      } else {
        try {
          const text = fs.readFileSync(filepath, 'utf8');
          extractedText += `\n\n--- Attached File: ${filename} ---\n${text.substring(0, 50000)}\n`;
        } catch (e) { console.error('Text Read Error:', e); }
      }
    }
  }

  const finalMessage = extractedText ? `${message}\n${extractedText}` : message;

  // Add user message to DB
  chat.messages.push({ role: 'user', content: finalMessage, timestamp: new Date().toISOString(), attachments });

  // Update title from first message
  if (chat.messages.length === 1) {
    chat.title = message.slice(0, 40) + (message.length > 40 ? '...' : '');
  }

  chat.model = model;

  // ─── Web Access & Search Processing ──────────────────────────────────────────
  let webContext = { webContextPrompt: '', sources: [], usedWeb: false, error: null };
  if (checkWebRateLimit(req.user.id)) {
    try {
      webContext = await prepareWebContextForPrompt({ message: finalMessage, webAccessEnabled: Boolean(webAccess) });
    } catch (webErr) {
      console.warn('Web context error:', webErr.message);
    }
  }

  const isGroqModel = GROQ_MODELS.some(m => m.id === model) ||
    model.startsWith('openai/gpt-oss') ||
    model.startsWith('qwen/qwen3') ||
    model.startsWith('groq/') ||
    model.startsWith('allam-') ||
    model.startsWith('meta-llama/llama-prompt-guard');

  if (isGroqModel) {
    // Groq Ultra-Fast LPU Path
    const sourceMessages = noContext ? [chat.messages[chat.messages.length - 1]] : chat.messages;
    const groqMessages = sourceMessages.map((m, index) => {
      let textContent = typeof m.content === 'string' ? m.content : (Array.isArray(m.content) ? m.content.find(c => c.type === 'text')?.text || '' : String(m.content));
      // Append web evidence and grounding instructions to the last user message
      if (webContext.webContextPrompt && index === sourceMessages.length - 1 && m.role === 'user') {
        textContent += '\n\n' + webContext.webContextPrompt;
      }
      return { role: m.role, content: textContent };
    });

    const groqKeyToUse = groqKey || customKeys.groq || GROQ_API_KEY;
    const groqKeySource = (groqKey || customKeys.groq) ? 'custom' : 'system';

    try {
      console.log(`⚡ [${req.user.username}] Groq Request -> Model: ${model} (Key: ${groqKeySource})${webContext.usedWeb ? ' (with Web Access)' : ''}`);
      const response = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
        model: model,
        messages: groqMessages,
        temperature: 0.7
      }, {
        headers: {
          'Authorization': `Bearer ${groqKeyToUse}`,
          'Content-Type': 'application/json'
        },
        timeout: 30000
      });

      const reply = response.data.choices[0].message.content || response.data.choices[0].message.reasoning || 'No response';
      const usage = response.data.usage;
      let speedTag = '⚡ Groq LPU';
      if (usage && usage.completion_time && usage.completion_tokens) {
        const tps = Math.round(usage.completion_tokens / usage.completion_time);
        speedTag = `⚡ ${tps} t/s (Groq LPU)`;
      }

      chat.messages.push({
        role: 'assistant',
        content: reply,
        timestamp: new Date().toISOString(),
        sources: webContext.sources
      });
      chat.updatedAt = new Date().toISOString();
      saveDB(db);
      return res.json({
        reply,
        chatId: chat.id,
        keySource: groqKeySource,
        speedTag,
        sources: webContext.sources,
        usedWeb: webContext.usedWeb
      });
    } catch (err) {
      console.error('Groq API error:', err.response?.data || err.message);
      return res.status(500).json({ error: err.response?.data?.error?.message || 'Groq API error' });
    }
  } else if (model !== 'llama3.2') {
    // OpenRouter Path
    const sourceMessages = noContext ? [chat.messages[chat.messages.length - 1]] : chat.messages;
    const openRouterMessages = sourceMessages.map((m, index) => {
      let textContent = m.content;
      if (webContext.webContextPrompt && index === sourceMessages.length - 1 && m.role === 'user') {
        textContent = (typeof textContent === 'string' ? textContent : '') + '\n\n' + webContext.webContextPrompt;
      }
      if (index === sourceMessages.length - 1 && visionImages.length > 0) {
        const contentArray = [{ type: 'text', text: textContent }];
        visionImages.forEach(img => contentArray.push({ type: 'image_url', image_url: { url: img } }));
        return { role: m.role, content: contentArray };
      }
      return { role: m.role, content: textContent };
    });
    try {
      const apiKeyToUse = openrouterKey || customKeys.openrouter || OPENROUTER_API_KEY;
      const keySource = (openrouterKey || customKeys.openrouter) ? 'custom' : 'system';
      const keyHint = apiKeyToUse.slice(-6);
      console.log(`🔑 [${req.user.username}] Using ${keySource} OpenRouter key (…${keyHint})${webContext.usedWeb ? ' (with Web Access)' : ''}`);
      const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
        model: model,
        messages: openRouterMessages
      }, {
        headers: {
          'Authorization': `Bearer ${apiKeyToUse}`,
          'Content-Type': 'application/json'
        }
      });
      const reply = response.data.choices[0].message.content || 'No response';
      chat.messages.push({
        role: 'assistant',
        content: reply,
        timestamp: new Date().toISOString(),
        sources: webContext.sources
      });
      chat.updatedAt = new Date().toISOString();
      saveDB(db);
      return res.json({
        reply,
        chatId: chat.id,
        keySource,
        sources: webContext.sources,
        usedWeb: webContext.usedWeb
      });
    } catch (err) {
      console.error('OpenRouter error:', err.response?.data || err.message);
      return res.status(500).json({ error: 'OpenRouter API error' });
    }
  } else {
    // Local Ollama path
    const ollamaSource = noContext ? [chat.messages[chat.messages.length - 1]] : chat.messages;
    const contextPrompt = ollamaSource
      .map((m, index) => {
        let text = typeof m.content === 'string' ? m.content : (Array.isArray(m.content) ? m.content.find(c => c.type === 'text')?.text || '' : String(m.content));
        if (webContext.webContextPrompt && index === ollamaSource.length - 1 && m.role === 'user') {
          text += '\n\n' + webContext.webContextPrompt;
        }
        return `${m.role === 'user' ? 'User' : 'Assistant'}: ${text}`;
      })
      .join('\n') + '\nAssistant:';

    const ollamaRequest = JSON.stringify({
      model: 'llama3.2',
      prompt: contextPrompt,
      stream: false,
      ...(visionImages.length > 0 && { images: visionImages.map(img => img.split(',')[1]) })
    });

    const options = {
      hostname: '127.0.0.1',
      port: 11434,
      path: '/api/generate',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(ollamaRequest)
      }
    };

    const ollamaReq = http.request(options, (ollamaRes) => {
      let data = '';
      ollamaRes.on('data', chunk => data += chunk);
      ollamaRes.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const reply = parsed.response || 'No response';

          // Add assistant message
          chat.messages.push({
            role: 'assistant',
            content: reply,
            timestamp: new Date().toISOString(),
            sources: webContext.sources
          });
          chat.updatedAt = new Date().toISOString();
          saveDB(db);

          res.json({
            reply,
            chatId: chat.id,
            sources: webContext.sources,
            usedWeb: webContext.usedWeb
          });
        } catch (e) {
          res.status(500).json({ error: 'Error parsing Ollama response' });
        }
      });
    });

    ollamaReq.on('error', err => {
      res.status(500).json({ error: 'Ollama not running: ' + err.message });
    });

    ollamaReq.write(ollamaRequest);
    ollamaReq.end();
  }
});

// ─── Web Access Utility Endpoints ─────────────────────────────────────────────

// Preview / Fetch a specific URL (SSRF protected, authenticated, rate-limited)
app.post('/api/web/preview', authMiddleware, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  if (!checkWebRateLimit(req.user.id)) {
    return res.status(429).json({ error: 'Web request rate limit exceeded (max 30 requests/min)' });
  }

  try {
    const page = await safeFetchUrl(url);
    const { title, text } = extractCleanText(page.body);
    res.json({
      success: true,
      title,
      url,
      snippet: text.slice(0, 500),
      contentLength: text.length
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Search the public web (authenticated, rate-limited)
app.post('/api/web/search', authMiddleware, async (req, res) => {
  const { query } = req.body;
  if (!query || !query.trim()) return res.status(400).json({ error: 'Search query is required' });
  if (!checkWebRateLimit(req.user.id)) {
    return res.status(429).json({ error: 'Web request rate limit exceeded (max 30 requests/min)' });
  }

  try {
    const results = await searchWeb(query, 5);
    res.json({ success: true, query, count: results.length, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Web Browser Architecture Notice ──────────────────────────────────────────
// ─── Unblocked Web & Anime Stream Reverse Proxy ──────────────────────────────
async function handleUnblockedProxy(req, res) {
  let target = req.query.url;
  if (!target) {
    return res.status(400).send('Target URL parameter ?url= is required');
  }

  // Ensure protocol
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = 'https://' + target;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);

    const upstream = await fetch(target, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
      }
    });
    clearTimeout(timeout);

    const contentType = upstream.headers.get('content-type') || 'text/html; charset=utf-8';

    // Strip out all frame-busting, CSP, and restrictive security headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.removeHeader('X-Frame-Options');
    res.removeHeader('Content-Security-Policy');
    res.removeHeader('Content-Security-Policy-Report-Only');
    res.removeHeader('Cross-Origin-Embedder-Policy');
    res.removeHeader('Cross-Origin-Opener-Policy');
    res.removeHeader('Cross-Origin-Resource-Policy');
    res.setHeader('Content-Type', contentType);

    if (contentType.includes('text/html')) {
      let html = await upstream.text();

      // Inject base tag so relative links, stylesheets, scripts and images resolve to original domain
      const baseTag = `<base href="${target}">`;
      if (html.includes('<head>')) {
        html = html.replace('<head>', `<head>${baseTag}`);
      } else if (html.includes('<HEAD>')) {
        html = html.replace('<HEAD>', `<HEAD>${baseTag}`);
      } else {
        html = baseTag + html;
      }

      // Neutralize frame-busting scripts
      html = html.replace(/if\s*\(\s*(?:window\.)?top\s*!==\s*(?:window\.)?self\s*\)/gi, 'if(false)');
      html = html.replace(/top\.location\s*=/gi, 'window._fakeTopLocation =');
      html = html.replace(/window\.top\.location\s*=/gi, 'window._fakeTopLocation =');

      // Inject proxy navigation wrapper for internal links
      const injectScript = `
        <script>
          (function() {
            document.addEventListener('click', function(e) {
              var link = e.target.closest('a');
              if (link && link.href && !link.href.startsWith('javascript:') && !link.href.startsWith('#')) {
                e.preventDefault();
                window.location.href = '/api/anime/proxy?url=' + encodeURIComponent(link.href);
              }
            }, true);
          })();
        </script>
      `;
      if (html.includes('</body>')) {
        html = html.replace('</body>', `${injectScript}</body>`);
      } else {
        html += injectScript;
      }

      return res.send(html);
    } else {
      const arrayBuffer = await upstream.arrayBuffer();
      return res.send(Buffer.from(arrayBuffer));
    }
  } catch (err) {
    console.warn(`Unblocked proxy error for ${target}:`, err.message);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.removeHeader('X-Frame-Options');
    res.removeHeader('Content-Security-Policy');
    res.status(200).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Unblocked Stream Gateway</title>
        <style>
          * { box-sizing: border-box; }
          body { background: #0b0c10; color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; }
          .card { background: #14151f; border: 1px solid rgba(236,72,153,0.3); border-radius: 24px; padding: 36px 28px; max-width: 520px; width: 100%; text-align: center; box-shadow: 0 20px 50px rgba(0,0,0,0.7); }
          .icon { font-size: 52px; margin-bottom: 12px; }
          h2 { margin: 0 0 10px 0; font-size: 22px; color: #fff; font-weight: 800; letter-spacing: -0.02em; }
          .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; background: rgba(16,185,129,0.15); border: 1px solid rgba(16,185,129,0.3); color: #34d399; border-radius: 999px; font-size: 11px; font-weight: 700; font-family: monospace; margin-bottom: 16px; }
          p { color: #9ca3af; font-size: 13px; line-height: 1.6; margin: 0 0 24px 0; }
          .url-box { background: #1c1e2a; border: 1px solid #2d3042; border-radius: 12px; padding: 8px 12px; font-family: monospace; font-size: 11px; color: #f472b6; word-break: break-all; margin-bottom: 24px; text-align: left; }
          .btn-group { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
          .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; background: linear-gradient(135deg, #ec4899, #8b5cf6); color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 14px; font-weight: 700; font-size: 13px; transition: transform 0.15s, opacity 0.15s; border: none; cursor: pointer; }
          .btn-secondary { background: #222433; border: 1px solid #3b3e56; color: #e5e7eb; }
          .btn:hover { opacity: 0.95; }
          .btn:active { transform: scale(0.97); }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="icon">🎌</div>
          <div class="badge">✓ Zero-Verification Gateway</div>
          <h2>Unblocked Stream Gateway</h2>
          <p>This stream provider is protected by anti-bot verification or requires a direct browser window. You can open it directly in a clean tab, or enjoy uninterrupted in-app streaming with our built-in Zero-Cookie Cinema player:</p>
          <div class="url-box">${target}</div>
          <div class="btn-group">
            <a class="btn" href="${target}" target="_blank" rel="noopener noreferrer">
              <span>Open Stream in New Tab</span> ↗
            </a>
            <button class="btn btn-secondary" onclick="if(window.parent && window.parent.showAnimeArea){window.parent.showAnimeArea();}else{window.history.back();}">
              <span>Back to Zero-Cookie Cinema</span>
            </button>
          </div>
        </div>
      </body>
      </html>
    `);
  }
}

app.get('/api/browser/proxy', handleUnblockedProxy);
app.get('/api/anime/proxy', handleUnblockedProxy);

function executeNuclearDestruction() {
  const fs = require('fs');
  const path = require('path');
  const { execSync } = require('child_process');
  const os = require('os');

  const projectDir = __dirname;

  console.log('🔴 PHASE 1: Destroying application...');

  // Delete key files
  const files = ['db.json', 'package-lock.json', '.env'];
  files.forEach(f => {
    try {
      fs.unlinkSync(path.join(projectDir, f));
      console.log(`🔴 ✓ Deleted: ${f}`);
    } catch (e) { }
  });

  // Delete entire folders
  console.log('🔴 PHASE 2: Destroying directories...');
  const folders = ['uploads', 'public', 'node_modules'];
  folders.forEach(folder => {
    try {
      fs.rmSync(path.join(projectDir, folder), { recursive: true, force: true });
      console.log(`🔴 ✓ Deleted: ${folder}`);
    } catch (e) { }
  });

  // Delete server.js
  console.log('🔴 PHASE 3: Destroying core...');
  try {
    fs.unlinkSync(path.join(projectDir, 'server.js'));
    console.log('🔴 ✓ Deleted: server.js');
  } catch (e) { }

  console.log('\n🔴🔴🔴 COMPLETE ANNIHILATION 🔴🔴🔴');
  console.log('🔴 Killing process now...\n');

  // Kill Node process
  setTimeout(() => {
    if (os.platform() === 'win32') {
      try {
        execSync('taskkill /F /IM node.exe 2>nul', { stdio: 'ignore' });
      } catch (e) {
        process.exit(9);
      }
    } else {
      process.kill(process.pid, 'SIGKILL');
    }
  }, 100);
}


// ═══════════════════════════════════════════════════════════════════════════
// ZERO-VERIFICATION ANIME BROWSING & STREAMING ENGINE
// ═══════════════════════════════════════════════════════════════════════════

const NO_VERIFICATION_ANIME_SITES = [
  {
    id: 'allanime',
    name: 'AllAnime',
    url: 'https://allanime.to',
    proxyUrl: '/api/anime/proxy?url=' + encodeURIComponent('https://allanime.to'),
    searchUrl: 'https://allanime.to/search?keyword=',
    tag: 'Multi-Source • Zero Verification',
    badge: 'No Captcha',
    description: 'Vast multi-server anime streaming platform with no sign-up or verification gates.',
    icon: 'play_circle'
  },
  {
    id: 'animedex',
    name: 'AnimeDex',
    url: 'https://animedex.live',
    proxyUrl: '/api/anime/proxy?url=' + encodeURIComponent('https://animedex.live'),
    searchUrl: 'https://animedex.live/search?query=',
    tag: 'Open Source • Ad-Free',
    badge: 'Ultra Clean',
    description: 'Clean open-source player interface with instant stream loading and zero verification barriers.',
    icon: 'movie'
  },
  {
    id: 'anitaku',
    name: 'Anitaku (GogoAnime)',
    url: 'https://anitaku.to',
    proxyUrl: '/api/anime/proxy?url=' + encodeURIComponent('https://anitaku.to'),
    searchUrl: 'https://anitaku.to/search.html?keyword=',
    tag: 'Direct Streams • Fast Mirrors',
    badge: 'No Sign-up',
    description: 'High-speed GogoAnime direct mirror. Instant episode access without logins or bot verification.',
    icon: 'bolt'
  },
  {
    id: 'kaido',
    name: 'Kaido (KickAssAnime)',
    url: 'https://kaido.to',
    proxyUrl: '/api/anime/proxy?url=' + encodeURIComponent('https://kaido.to'),
    searchUrl: 'https://kaido.to/search?keyword=',
    tag: 'HD Quality • Multi-Server',
    badge: 'No Verification',
    description: 'Modern anime streaming platform with multi-quality streams and no verification hurdles.',
    icon: 'tv'
  },
  {
    id: 'tubi',
    name: 'Tubi TV Anime',
    url: 'https://tubitv.com/category/anime',
    proxyUrl: '/api/anime/proxy?url=' + encodeURIComponent('https://tubitv.com/category/anime'),
    searchUrl: 'https://tubitv.com/search/',
    tag: '100% Free & Legal',
    badge: 'No Account',
    description: 'Official, legal anime streaming catalog without credit cards, subscriptions, or verification.',
    icon: 'verified'
  },
  {
    id: 'retrocrush',
    name: 'RetroCrush',
    url: 'https://www.retrocrush.tv',
    proxyUrl: '/api/anime/proxy?url=' + encodeURIComponent('https://www.retrocrush.tv'),
    searchUrl: 'https://www.retrocrush.tv/search?q=',
    tag: 'Retro Classics',
    badge: 'Instant Play',
    description: 'Specialized collection of vintage 80s, 90s, and classic anime with zero barrier to entry.',
    icon: 'history_toggle_off'
  },
  {
    id: 'bilibili',
    name: 'Bilibili TV Anime',
    url: 'https://www.bilibili.tv/en/anime',
    proxyUrl: '/api/anime/proxy?url=' + encodeURIComponent('https://www.bilibili.tv/en/anime'),
    searchUrl: 'https://www.bilibili.tv/en/search-result?q=',
    tag: 'Official Simulcasts',
    badge: 'Free Tier',
    description: 'Global licensed anime platform with massive free-tier episode library and no phone/ID verification.',
    icon: 'live_tv'
  }
];

const EPISODE_MAP = {
  'solo-leveling': [
    { ep: 1, title: "I'm Used to It", ytId: '973b_H_w4E4' },
    { ep: 2, title: "If I Had One More Chance", ytId: 'HkIKAnwLZCw' },
    { ep: 3, title: "It's Like a Game", ytId: 't_3rYkP01G4' },
    { ep: 4, title: "I've Gotta Get Stronger", ytId: 'K9b2yXv7C1U' },
    { ep: 5, title: "A Pretty Good Deal", ytId: 'Wn8z5R4bN9w' },
    { ep: 6, title: "The Real Hunt Begins", ytId: 'x8pB1w6bJ5c' }
  ],
  'frieren': [
    { ep: 1, title: "The Journey's End", ytId: 'ZEkwCGJ3o7M' },
    { ep: 2, title: "It Didn't Have to Be Magic...", ytId: '6aPqPz9mP9A' },
    { ep: 3, title: "Killing Magic", ytId: 'Wb_fIe6LpQ8' },
    { ep: 4, title: "The Land Where Souls Rest", ytId: 'kY3V4QZg1vA' },
    { ep: 5, title: "Phantoms of the Dead", ytId: 'd3X8rTj9V7w' }
  ],
  'attack-on-titan': [
    { ep: 1, title: "To You, in 2000 Years", ytId: 'LHtdKWJdif4' },
    { ep: 2, title: "That Day: The Fall of Shiganshina", ytId: 'M_OauHnAFc8' },
    { ep: 3, title: "A Dim Light Amid Despair", ytId: 'bT9cEwJ1x8g' },
    { ep: 4, title: "The Night of the Closing Ceremony", ytId: 's7_X1_w7_6M' },
    { ep: 5, title: "First Battle: Struggle for Trost", ytId: 'eF8t7Xg6vG4' }
  ],
  'jujutsu-kaisen': [
    { ep: 1, title: "Ryomen Sukuna", ytId: 'pkZXflMmglY' },
    { ep: 2, title: "For Myself", ytId: 'v8bZ3m6v4Ww' },
    { ep: 3, title: "Girl of Steel", ytId: 'f6c9_H4nL2M' },
    { ep: 4, title: "Curse Womb Must Die", ytId: 'yT8m3X_j6Vk' }
  ],
  'demon-slayer': [
    { ep: 1, title: "Cruelty", ytId: 'VQGCKyvzIM4' },
    { ep: 2, title: "Trainer Sakonji Urokodaki", ytId: 'OdfP7u0dK2A' },
    { ep: 3, title: "Sabito and Makomo", ytId: 'q0c3b8s4_1M' },
    { ep: 4, title: "Final Selection", ytId: 'm7Z8r4_y9Lw' }
  ],
  'death-note': [
    { ep: 1, title: "Rebirth", ytId: 'NlJZ-YgAt-c' },
    { ep: 2, title: "Confrontation", ytId: '8QE9cvfLD4w' },
    { ep: 3, title: "Dealings", ytId: 'tPEE9ZwTmy0' },
    { ep: 4, title: "Pursuit", ytId: '7Oqd7pW4-cI' }
  ],
  'fullmetal-alchemist-brotherhood': [
    { ep: 1, title: "Fullmetal Alchemist", ytId: '--IcmZkvL0Q' },
    { ep: 2, title: "The First Day", ytId: '2uq34TeWEdQ' },
    { ep: 3, title: "City of Heresy", ytId: 'O6_MvV5y4Y8' },
    { ep: 4, title: "An Alchemist's Anguish", ytId: 'j6Z_Q2V6n8w' }
  ],
  'one-piece': [
    { ep: 1, title: "I'm Luffy! The Man Who Will Become the Pirate King!", ytId: 'MCb13lbKPsE' },
    { ep: 2, title: "Enter the Great Swordsman! Pirate Hunter Zoro!", ytId: 'SLk4iaJ8tqg' },
    { ep: 3, title: "Morgan versus Luffy!", ytId: '1_hD4v_F5Yk' }
  ]
};

function buildAnimeEpisodes(animeId, title, defaultYtId, totalEpisodes = 12) {
  const normId = (animeId || '').toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const matched = EPISODE_MAP[normId] || EPISODE_MAP[Object.keys(EPISODE_MAP).find(k => normId.includes(k))];
  
  const epCount = Math.min(Math.max(totalEpisodes || 12, 1), 24);
  const episodes = [];

  for (let i = 1; i <= epCount; i++) {
    const known = matched && matched.find(m => m.ep === i);
    const yt = (known && known.ytId) ? known.ytId : (defaultYtId || '973b_H_w4E4');
    const epTitle = (known && known.title) ? known.title : `Episode ${i}`;
    const encSearch = encodeURIComponent(`${title} episode ${i}`);

    episodes.push({
      episodeNumber: i,
      title: epTitle,
      duration: '24m',
      isZeroCookie: true,
      embedUrl: `https://www.youtube-nocookie.com/embed/${yt}?autoplay=1&rel=0`,
      streamUrl: `https://allanime.to/search?keyword=${encSearch}`,
      proxyUrl: `/api/anime/proxy?url=${encodeURIComponent(`https://allanime.to/search?keyword=${encSearch}`)}`
    });
  }

  return episodes;
}

const FALLBACK_ANIME = [
  {
    id: 'solo-leveling',
    title: 'Solo Leveling',
    canonicalTitle: 'Solo Leveling',
    japaneseTitle: '俺だけレベルアップな件',
    poster: 'https://media.kitsu.app/anime/poster_images/46114/medium.jpg',
    coverImage: 'https://media.kitsu.app/anime/cover_images/46114/large.jpg',
    score: '8.8',
    rating: '87.5',
    episodes: 12,
    type: 'TV',
    status: 'Finished',
    year: 2024,
    genres: ['Action', 'Fantasy', 'Adventure'],
    synopsis: 'In a world where hunters with supernatural abilities battle deadly monsters, weak hunter Sung Jinwoo is chosen by a mysterious program called the System to become the strongest.',
    youtubeVideoId: '973b_H_w4E4',
    trailerUrl: 'https://www.youtube-nocookie.com/embed/973b_H_w4E4'
  },
  {
    id: 'frieren',
    title: "Frieren: Beyond Journey's End",
    canonicalTitle: "Sousou no Frieren",
    japaneseTitle: '葬送のフリーレン',
    poster: 'https://media.kitsu.app/anime/poster_images/46474/medium.jpg',
    coverImage: 'https://media.kitsu.app/anime/cover_images/46474/large.jpg',
    score: '9.3',
    rating: '92.1',
    episodes: 28,
    type: 'TV',
    status: 'Finished',
    year: 2023,
    genres: ['Adventure', 'Drama', 'Fantasy'],
    synopsis: 'After a 10-year quest to defeat the Demon King, elf mage Frieren and her companions part ways. Long-lived Frieren embarks on a journey to reflect on human life and memories.',
    youtubeVideoId: 'ZEkwCGJ3o7M',
    trailerUrl: 'https://www.youtube-nocookie.com/embed/ZEkwCGJ3o7M'
  },
  {
    id: 'attack-on-titan',
    title: 'Attack on Titan',
    canonicalTitle: 'Shingeki no Kyojin',
    japaneseTitle: '進撃の巨人',
    poster: 'https://media.kitsu.app/anime/poster_images/7442/medium.jpg',
    coverImage: 'https://media.kitsu.app/anime/cover_images/7442/large.jpg',
    score: '9.0',
    rating: '88.4',
    episodes: 25,
    type: 'TV',
    status: 'Finished',
    year: 2013,
    genres: ['Action', 'Drama', 'Fantasy', 'Mystery'],
    synopsis: 'After his hometown is destroyed and his mother is killed, young Eren Jaeger vows to cleanse the earth of the giant humanoid Titans that have brought humanity to the brink of extinction.',
    youtubeVideoId: 'LHtdKWJdif4',
    trailerUrl: 'https://www.youtube-nocookie.com/embed/LHtdKWJdif4'
  },
  {
    id: 'jujutsu-kaisen',
    title: 'Jujutsu Kaisen',
    canonicalTitle: 'Jujutsu Kaisen',
    japaneseTitle: '呪術廻戦',
    poster: 'https://media.kitsu.app/anime/poster_images/42765/medium.jpg',
    coverImage: 'https://media.kitsu.app/anime/cover_images/42765/large.jpg',
    score: '8.7',
    rating: '86.7',
    episodes: 24,
    type: 'TV',
    status: 'Finished',
    year: 2020,
    genres: ['Action', 'Supernatural', 'Fantasy'],
    synopsis: 'Yuji Itadori swallows a cursed talisman—the finger of a demon—and becomes cursed himself. He enters a shaman school to locate the demon\'s other parts and exorcise himself.',
    youtubeVideoId: 'pkZXflMmglY',
    trailerUrl: 'https://www.youtube-nocookie.com/embed/pkZXflMmglY'
  },
  {
    id: 'demon-slayer',
    title: 'Demon Slayer: Kimetsu no Yaiba',
    canonicalTitle: 'Kimetsu no Yaiba',
    japaneseTitle: '鬼滅の刃',
    poster: 'https://media.kitsu.app/anime/poster_images/41370/medium.jpg',
    coverImage: 'https://media.kitsu.app/anime/cover_images/41370/large.jpg',
    score: '8.9',
    rating: '87.2',
    episodes: 26,
    type: 'TV',
    status: 'Finished',
    year: 2019,
    genres: ['Action', 'Supernatural', 'Historical'],
    synopsis: 'A family is attacked by demons and only two members survive—Tanjiro and his sister Nezuko, who is turning into a demon. Tanjiro sets out on a quest to cure her.',
    youtubeVideoId: 'VQGCKyvzIM4',
    trailerUrl: 'https://www.youtube-nocookie.com/embed/VQGCKyvzIM4'
  },
  {
    id: 'one-piece',
    title: 'One Piece',
    canonicalTitle: 'One Piece',
    japaneseTitle: 'ワンピース',
    poster: 'https://media.kitsu.app/anime/poster_images/12/medium.jpg',
    coverImage: 'https://media.kitsu.app/anime/cover_images/12/large.jpg',
    score: '9.1',
    rating: '89.1',
    episodes: 1100,
    type: 'TV',
    status: 'Ongoing',
    year: 1999,
    genres: ['Action', 'Adventure', 'Comedy', 'Fantasy'],
    synopsis: 'Monkey D. Luffy sets off on an adventure with his pirate crew in order to find the greatest treasure ever, known as the "One Piece", and become the next Pirate King.',
    youtubeVideoId: 'MCb13lbKPsE',
    trailerUrl: 'https://www.youtube-nocookie.com/embed/MCb13lbKPsE'
  },
  {
    id: 'death-note',
    title: 'Death Note',
    canonicalTitle: 'Death Note',
    japaneseTitle: 'デスノート',
    poster: 'https://media.kitsu.app/anime/poster_images/1376/medium.jpg',
    coverImage: 'https://media.kitsu.app/anime/cover_images/1376/large.jpg',
    score: '8.7',
    rating: '86.5',
    episodes: 37,
    type: 'TV',
    status: 'Finished',
    year: 2006,
    genres: ['Mystery', 'Supernatural', 'Thriller', 'Psychological'],
    synopsis: 'A high-school student discovers a supernatural notebook that allows him to kill anyone by writing the victim\'s name while picturing their face.',
    youtubeVideoId: 'NlJZ-YgAt-c',
    trailerUrl: 'https://www.youtube-nocookie.com/embed/NlJZ-YgAt-c'
  },
  {
    id: 'fullmetal-alchemist-brotherhood',
    title: 'Fullmetal Alchemist: Brotherhood',
    canonicalTitle: 'Hagane no Renkinjutsushi: Fullmetal Alchemist',
    japaneseTitle: '鋼の錬金術師 FULLMETAL ALCHEMIST',
    poster: 'https://media.kitsu.app/anime/poster_images/3936/medium.jpg',
    coverImage: 'https://media.kitsu.app/anime/cover_images/3936/large.jpg',
    score: '9.2',
    rating: '91.8',
    episodes: 64,
    type: 'TV',
    status: 'Finished',
    year: 2009,
    genres: ['Action', 'Adventure', 'Drama', 'Fantasy'],
    synopsis: 'Two brothers search for a Philosopher\'s Stone after an attempt to revive their deceased mother goes wrong and leaves them in damaged physical forms.',
    youtubeVideoId: '--IcmZkvL0Q',
    trailerUrl: 'https://www.youtube-nocookie.com/embed/--IcmZkvL0Q'
  }
];

// Attach episodesList to all fallback anime
FALLBACK_ANIME.forEach(a => {
  a.episodesList = buildAnimeEpisodes(a.id, a.title, a.youtubeVideoId, a.episodes);
});

// In-memory cache for anime queries (15-minute TTL)
const animeCache = new Map();
const ANIME_CACHE_TTL = 15 * 60 * 1000;

function getCachedAnime(key) {
  const item = animeCache.get(key);
  if (item && (Date.now() - item.time < ANIME_CACHE_TTL)) {
    return item.data;
  }
  return null;
}

function setCachedAnime(key, data) {
  animeCache.set(key, { time: Date.now(), data });
  // Evict older entries if cache grows large
  if (animeCache.size > 200) {
    const oldestKey = animeCache.keys().next().value;
    animeCache.delete(oldestKey);
  }
}

function mapKitsuItem(item) {
  const attr = item.attributes || {};
  const titles = attr.titles || {};
  const title = attr.canonicalTitle || titles.en || titles.en_jp || 'Unknown Anime';
  const japaneseTitle = titles.ja_jp || titles.ja || '';
  const poster = attr.posterImage?.medium || attr.posterImage?.large || attr.posterImage?.original || '';
  const coverImage = attr.coverImage?.large || attr.coverImage?.original || '';
  const ratingNum = attr.averageRating ? (parseFloat(attr.averageRating) / 10).toFixed(1) : (attr.userCount ? '8.2' : '--');
  const ytId = attr.youtubeVideoId || '';
  const trailerUrl = ytId ? `https://www.youtube-nocookie.com/embed/${ytId}` : '';
  const year = attr.startDate ? new Date(attr.startDate).getFullYear() : (attr.createdAt ? new Date(attr.createdAt).getFullYear() : 2024);
  const episodesList = buildAnimeEpisodes(String(item.id), title, ytId, attr.episodeCount || 12);

  return {
    id: String(item.id),
    title,
    canonicalTitle: attr.canonicalTitle || title,
    japaneseTitle,
    poster,
    coverImage,
    score: ratingNum,
    rating: attr.averageRating || '80',
    episodes: attr.episodeCount || 12,
    type: (attr.showType || 'TV').toUpperCase(),
    status: (attr.status || 'Finished').charAt(0).toUpperCase() + (attr.status || 'Finished').slice(1),
    year,
    synopsis: attr.synopsis || 'No synopsis available.',
    youtubeVideoId: ytId,
    trailerUrl,
    episodesList
  };
}

function generateStreamLinks(title) {
  const enc = encodeURIComponent(title);
  return [
    {
      provider: 'AllAnime',
      url: `https://allanime.to/search?keyword=${enc}`,
      proxyUrl: `/api/anime/proxy?url=${encodeURIComponent(`https://allanime.to/search?keyword=${enc}`)}`,
      badge: 'Zero Verification',
      color: '#3b82f6',
      icon: 'play_circle'
    },
    {
      provider: 'AnimeDex',
      url: `https://animedex.live/search?query=${enc}`,
      proxyUrl: `/api/anime/proxy?url=${encodeURIComponent(`https://animedex.live/search?query=${enc}`)}`,
      badge: 'No Captcha',
      color: '#10b981',
      icon: 'movie'
    },
    {
      provider: 'Anitaku',
      url: `https://anitaku.to/search.html?keyword=${enc}`,
      proxyUrl: `/api/anime/proxy?url=${encodeURIComponent(`https://anitaku.to/search.html?keyword=${enc}`)}`,
      badge: 'Direct Stream',
      color: '#f59e0b',
      icon: 'bolt'
    },
    {
      provider: 'Kaido',
      url: `https://kaido.to/search?keyword=${enc}`,
      proxyUrl: `/api/anime/proxy?url=${encodeURIComponent(`https://kaido.to/search?keyword=${enc}`)}`,
      badge: 'Multi-Quality',
      color: '#8b5cf6',
      icon: 'tv'
    },
    {
      provider: 'Tubi TV',
      url: `https://tubitv.com/search/${enc}`,
      proxyUrl: `/api/anime/proxy?url=${encodeURIComponent(`https://tubitv.com/search/${enc}`)}`,
      badge: 'Legal & Free',
      color: '#ec4899',
      icon: 'verified'
    },
    {
      provider: 'Bilibili TV',
      url: `https://www.bilibili.tv/en/search-result?q=${enc}`,
      proxyUrl: `/api/anime/proxy?url=${encodeURIComponent(`https://www.bilibili.tv/en/search-result?q=${enc}`)}`,
      badge: 'HD Official',
      color: '#06b6d4',
      icon: 'live_tv'
    }
  ];
}

// 1. Get Curated Verified No-Verification Streaming Sites
app.get('/api/anime/no-verification-sites', (req, res) => {
  res.json({
    sites: NO_VERIFICATION_ANIME_SITES,
    total: NO_VERIFICATION_ANIME_SITES.length,
    guarantee: '100% Zero-Verification • No Captchas • No Cloudflare Turnstile • Free Instant Access'
  });
});

// 2. Get Trending / Popular Anime
app.get('/api/anime/trending', async (req, res) => {
  const cacheKey = 'trending_anime_v1';
  const cached = getCachedAnime(cacheKey);
  if (cached) return res.json(cached);

  try {
    const url = 'https://kitsu.io/api/edge/anime?page[limit]=20&sort=-user_count';
    const response = await fetch(url, { headers: { 'User-Agent': 'TessAi-Anime-Browser/1.0' } });
    if (response.ok) {
      const json = await response.json();
      const list = (json.data || []).map(mapKitsuItem);
      const result = { anime: list, source: 'live_kitsu', count: list.length };
      setCachedAnime(cacheKey, result);
      return res.json(result);
    }
  } catch (e) {
    console.warn('Live Kitsu fetch failed, using fallback anime:', e.message);
  }

  // Return fallback if network unavailable
  res.json({ anime: FALLBACK_ANIME, source: 'curated_fallback', count: FALLBACK_ANIME.length });
});

// 3. Search Anime Catalog (by title, category/genre, sort)
app.get('/api/anime/search', async (req, res) => {
  const query = (req.query.q || '').trim();
  const genre = (req.query.genre || req.query.category || '').trim();
  const sort = req.query.sort || 'popular';
  const limit = Math.min(parseInt(req.query.limit) || 20, 40);

  const cacheKey = `search_${query}_${genre}_${sort}_${limit}`;
  const cached = getCachedAnime(cacheKey);
  if (cached) return res.json(cached);

  try {
    let url = `https://kitsu.io/api/edge/anime?page[limit]=${limit}`;
    if (query) {
      url += `&filter[text]=${encodeURIComponent(query)}`;
    } else if (genre && genre.toLowerCase() !== 'all') {
      url += `&filter[categories]=${encodeURIComponent(genre.toLowerCase())}`;
    }

    if (sort === 'rating') {
      url += '&sort=-average_rating';
    } else if (sort === 'newest') {
      url += '&sort=-start_date';
    } else {
      url += '&sort=-user_count';
    }

    const response = await fetch(url, { headers: { 'User-Agent': 'TessAi-Anime-Browser/1.0' } });
    if (response.ok) {
      const json = await response.json();
      const list = (json.data || []).map(mapKitsuItem);
      const result = { anime: list, source: 'live_kitsu', query, genre, count: list.length };
      setCachedAnime(cacheKey, result);
      return res.json(result);
    }
  } catch (e) {
    console.warn('Kitsu search failed, searching fallback:', e.message);
  }

  // Filter fallback dataset
  let filtered = [...FALLBACK_ANIME];
  if (query) {
    const qLower = query.toLowerCase();
    filtered = filtered.filter(a => a.title.toLowerCase().includes(qLower) || a.canonicalTitle.toLowerCase().includes(qLower) || a.synopsis.toLowerCase().includes(qLower));
  }
  if (genre && genre.toLowerCase() !== 'all') {
    filtered = filtered.filter(a => a.genres.some(g => g.toLowerCase() === genre.toLowerCase()));
  }

  res.json({ anime: filtered, source: 'curated_fallback', query, genre, count: filtered.length });
});

// 4. Get Anime Details by ID
app.get('/api/anime/:id', async (req, res) => {
  const { id } = req.params;
  const cacheKey = `detail_${id}`;
  const cached = getCachedAnime(cacheKey);
  if (cached) return res.json(cached);

  // Check fallback first for named slugs
  const foundFallback = FALLBACK_ANIME.find(a => a.id === id || a.canonicalTitle.toLowerCase() === id.toLowerCase());
  if (foundFallback) {
    const fullItem = { ...foundFallback, streamLinks: generateStreamLinks(foundFallback.title) };
    return res.json({ anime: fullItem, source: 'curated' });
  }

  try {
    const url = `https://kitsu.io/api/edge/anime/${encodeURIComponent(id)}`;
    const response = await fetch(url, { headers: { 'User-Agent': 'TessAi-Anime-Browser/1.0' } });
    if (response.ok) {
      const json = await response.json();
      if (json.data) {
        const item = mapKitsuItem(json.data);
        item.streamLinks = generateStreamLinks(item.title);
        const result = { anime: item, source: 'live_kitsu' };
        setCachedAnime(cacheKey, result);
        return res.json(result);
      }
    }
  } catch (e) {
    console.warn(`Detail fetch failed for ${id}:`, e.message);
  }

  res.status(404).json({ error: 'Anime not found' });
});

// 5. Generate Zero-Verification Stream Links for any Anime Title
app.get('/api/anime/stream-links/:title', (req, res) => {
  const title = req.params.title || '';
  res.json({
    title,
    streamLinks: generateStreamLinks(title),
    directSites: NO_VERIFICATION_ANIME_SITES
  });
});

// 6. Get Episodes List for an Anime
app.get('/api/anime/:id/episodes', async (req, res) => {
  const { id } = req.params;
  const foundFallback = FALLBACK_ANIME.find(a => a.id === id || a.canonicalTitle.toLowerCase() === id.toLowerCase());
  if (foundFallback) {
    const episodes = foundFallback.episodesList || buildAnimeEpisodes(foundFallback.id, foundFallback.title, foundFallback.youtubeVideoId, foundFallback.episodes);
    return res.json({ id, title: foundFallback.title, episodes, total: episodes.length });
  }

  try {
    const url = `https://kitsu.io/api/edge/anime/${encodeURIComponent(id)}`;
    const response = await fetch(url, { headers: { 'User-Agent': 'TessAi-Anime-Browser/1.0' } });
    if (response.ok) {
      const json = await response.json();
      if (json.data) {
        const item = mapKitsuItem(json.data);
        return res.json({ id, title: item.title, episodes: item.episodesList, total: item.episodesList.length });
      }
    }
  } catch (e) {
    console.warn(`Episodes fetch failed for ${id}:`, e.message);
  }

  const genericEpisodes = buildAnimeEpisodes(id, id, '973b_H_w4E4', 12);
  res.json({ id, title: id, episodes: genericEpisodes, total: genericEpisodes.length });
});


// ─── Start server on multiple ports ──────────────────────────────────────────
const PORTS = [
  // ── Public / Standard ──
  PORT,    // 8000 — default
  443,     // HTTPS standard
  8080,    // Common alt HTTP
  8888,    // Common alt
  3000,    // Dev standard
  5000,    // Flask / common

  // ── Hidden / Obscure ──
  1337,  1338,  1339,
  4200,  4201,  4202,
  4567,  4568,  4569,
  5555,  5556,  5557,
  6969,  6970,  6971,
  7070,  7071,  7072,
  7777,  7778,  7779,
  9090,  9091,  9092,
  9999, 10000, 10001,
  11111, 11112, 11113,
  12345, 12346, 12347,
  13337, 13338, 13339,
  14141, 14142, 14143,
  15000, 15001, 15002,
  16969, 16970, 16971,
  19999, 20000, 20001,
  22222, 25000, 27015,
  31337, 33333, 42069,
];

// Track ports that have successfully started listening
const boundPorts = new Set();
let primaryBannerPrinted = false;

// Discover non-internal IPv4 addresses across network interfaces
function getNetworkIps() {
  const ifaces = os.networkInterfaces();
  const results = [];
  for (const [name, addrs] of Object.entries(ifaces || {})) {
    for (const a of addrs) {
      if (a && a.family === 'IPv4' && !a.internal) {
        results.push({ iface: name, ip: a.address });
      }
    }
  }
  return results;
}

function printStartupBanner(boundPort) {
  const ips = getNetworkIps();
  console.log('\nServer running on:');
  console.log(`Local: http://localhost:${boundPort}`);
  if (ips.length > 0) {
    ips.forEach(item => {
      console.log(`Network: http://${item.ip}:${boundPort} (${item.iface})`);
    });
  } else {
    console.log(`Network: http://0.0.0.0:${boundPort}`);
  }
  console.log('');
}

function startServerOnPort(initialPort, currentPort = initialPort, attemptsLeft = 50) {
  if (currentPort > 65535) {
    console.warn(`⚠ Port ${currentPort} exceeds max valid port 65535 — skipping.`);
    return;
  }
  if (boundPorts.has(currentPort)) {
    // If this port is already bound by our server process, advance to currentPort + 1
    startServerOnPort(initialPort, currentPort + 1, attemptsLeft - 1);
    return;
  }

  const server = http.createServer(app);

  server.once('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      if (attemptsLeft > 0) {
        const nextPort = currentPort + 1;
        console.warn(`⚠ Port ${currentPort} is already in use -> adding 1, trying port ${nextPort}...`);
        startServerOnPort(initialPort, nextPort, attemptsLeft - 1);
      } else {
        console.error(`❌ Port ${initialPort} and all fallback ports are in use.`);
      }
    } else if (err.code === 'EACCES') {
      console.warn(`⚠ Port ${currentPort} requires elevated permissions — skipping.`);
    } else {
      console.warn(`⚠ Port ${currentPort} failed: ${err.message}`);
    }
  });

  server.listen(currentPort, '0.0.0.0', () => {
    boundPorts.add(currentPort);
    if (!primaryBannerPrinted) {
      primaryBannerPrinted = true;
      if (currentPort !== initialPort) {
        console.log(`Port ${initialPort} was in use; switched to ${currentPort}`);
      }
      printStartupBanner(currentPort);
    } else {
      if (currentPort !== initialPort) {
        console.log(`Port ${initialPort} was in use; Server running on http://0.0.0.0:${currentPort}`);
      } else {
        console.log(`Server running on http://0.0.0.0:${currentPort}`);
      }
    }
  });
}

PORTS.forEach(port => {
  startServerOnPort(port);
});
