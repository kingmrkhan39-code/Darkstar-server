const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execFile } = require('child_process');
const os = require('os');
const pino = require('pino');
const chalk = require('chalk');

const app = express();
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
const PORT = process.env.PORT || 25448;

// Persistent server uptime anchor. Keeps the panel uptime across normal process restarts.
const serverStatePath = path.join(process.cwd(), 'server-state.json');
function loadServerStartTime() {
  try {
    if (fs.existsSync(serverStatePath)) {
      const state = JSON.parse(fs.readFileSync(serverStatePath, 'utf8'));
      if (Number.isFinite(Number(state.firstStartedAt))) return Number(state.firstStartedAt);
    }
  } catch (e) {}
  const firstStartedAt = Date.now();
  try { fs.writeFileSync(serverStatePath, JSON.stringify({ firstStartedAt }, null, 2), 'utf8'); } catch (e) {}
  return firstStartedAt;
}
const SERVER_START_TIME = loadServerStartTime();

// System/network monitor samples.
let lastNetworkSample = null;
let lastNetworkSampleAt = 0;

// Reconnect config
const RECONNECT_MAX = 6;
const RECONNECT_DELAY_MS = 4000; // 4 seconds
const SESSION_TIMEOUT_MS = 60 * 60 * 1000; // 1 hour

// Outgoing message acknowledgements. This is only used to observe delivery
// state; it never creates a second sender loop or sends duplicate messages.

// Prune config
const MAX_PREKEY_FILES = parseInt(process.env.MAX_PREKEY_FILES || '20', 10);
const MAX_SENDER_KEY_FILES = parseInt(process.env.MAX_SENDER_KEY_FILES || '5', 10);
const MAX_SESSION_FILES = parseInt(process.env.MAX_SESSION_FILES || '10', 10);
const PRUNE_DEBOUNCE_MS = parseInt(process.env.PRUNE_DEBOUNCE_MS || '2000', 10);
const GLOBAL_PRUNE_INTERVAL_MS = parseInt(process.env.GLOBAL_PRUNE_INTERVAL_MS || (60 * 60 * 1000).toString(), 10);

// Directories
const uploadsDir = path.join(process.cwd(), 'uploads');
const sessionsRoot = path.join(process.cwd(), 'uploaded_sessions');
const usersFilePath = path.join(process.cwd(), 'users.json');
const approvalFilePath = path.join(process.cwd(), 'approval.txt');
const approvalRequestsPath = path.join(process.cwd(), 'approval-requests.json');
const APPROVAL_COOKIE = 'wa_approval_key';
const APPROVAL_MAX_AGE = 31536000;

function parseCookieValue(req, name) {
  return parseCookies(req)[name] || '';
}

function makeApprovalKey() {
  return crypto.randomBytes(7).toString('hex').toUpperCase();
}

function getOrCreateApprovalKey(req, res) {
  let key = parseCookieValue(req, APPROVAL_COOKIE).trim().toUpperCase();
  if (!/^[A-F0-9]{14}$/.test(key)) {
    key = makeApprovalKey();
    const secure = process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true';
    const parts = [`${APPROVAL_COOKIE}=${encodeURIComponent(key)}`, 'Path=/', 'SameSite=Strict', `Max-Age=${APPROVAL_MAX_AGE}`];
    if (secure) parts.push('Secure');
    res.append('Set-Cookie', parts.join('; '));
  }
  return key;
}

function loadApprovalRequests() {
  try {
    if (fs.existsSync(approvalRequestsPath)) return JSON.parse(fs.readFileSync(approvalRequestsPath, 'utf8')) || {};
  } catch (e) {}
  return {};
}

function saveApprovalRequests(data) {
  try { fs.writeFileSync(approvalRequestsPath, JSON.stringify(data, null, 2), 'utf8'); } catch (e) {}
}

function isApprovalCookieApproved(req) {
  const key = parseCookieValue(req, APPROVAL_COOKIE).trim().toUpperCase();
  return !!key && isKeyApproved(key);
}


if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(sessionsRoot)) fs.mkdirSync(sessionsRoot, { recursive: true });

function mimeTypeForFile(filePath) {
  const ext = path.extname(String(filePath || '')).toLowerCase();
  const map = {
    '.pdf':'application/pdf','.doc':'application/msword','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls':'application/vnd.ms-excel','.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.ppt':'application/vnd.ms-powerpoint','.pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.txt':'text/plain','.csv':'text/csv','.zip':'application/zip','.rar':'application/vnd.rar','.7z':'application/x-7z-compressed'
  };
  return map[ext] || 'application/octet-stream';
}

// Initialize approval file if not exists
if (!fs.existsSync(approvalFilePath)) {
  fs.writeFileSync(approvalFilePath, '', 'utf8');
  console.log(chalk.yellow('[OK] approval.txt file created'));
}

// Initialize users file with admin
function initializeUsers() {
  const adminUsername = String(process.env.ADMIN_USERNAME || '').trim();
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');

  if (!fs.existsSync(usersFilePath)) {
  const adminUsername = 'Saimbaba905284';
  const adminPassword = 'Saimbaba905284';

  if (!adminUsername || adminPassword.length < 12) {
    throw new Error(
      'First startup requires ADMIN_USERNAME and ADMIN_PASSWORD (minimum 12 characters).'
    );
  }

  const salt = crypto.randomBytes(16).toString('hex');

  const users = {
    admin: {
      username: adminUsername,
      password: '',
      passwordSalt: salt,
      passwordHash: hashPassword(adminPassword, salt),
      role: 'admin',
      status: 'approved',
      primaryAdmin: true,
      createdAt: new Date().toISOString()
    }
  };

  // Iske neeche tumhare original code mein jo users file save/write
  // wala code hai, woh same rehna chahiye.
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
    console.log(chalk.green('[OK] Admin user created from environment configuration'));
    return;
  }

  // If an explicit admin password is supplied, rotate the primary admin password
  // without putting the username/password into browser-delivered source code.
  try {
    const users = loadUsers();
    let primaryEntry = Object.entries(users).find(([, u]) => u && u.primaryAdmin);
    if (!primaryEntry) primaryEntry = Object.entries(users).find(([, u]) => u && u.role === 'admin');
    if (primaryEntry) {
      const [id, user] = primaryEntry;
      user.role = 'admin';
      user.status = 'approved';
      user.primaryAdmin = true;
      if (adminUsername) user.username = adminUsername;
      if (adminPassword.length >= 12) {
        const salt = crypto.randomBytes(16).toString('hex');
        user.password = '';
        user.passwordSalt = salt;
        user.passwordHash = hashPassword(adminPassword, salt);
        invalidateUserTokens(user.username);
      }
      users[id] = user;
      saveUsers(users);
    }
  } catch (e) {
    logger.error('Admin initialization error', e?.message || e);
  }
}

// Password hashing
function hashPassword(password, salt) {
  if (salt) return crypto.scryptSync(String(password), String(salt), 64).toString('hex');
  return crypto.createHash('sha256').update(String(password)).digest('hex');
}

function verifyPassword(password, user) {
  if (!user) return false;
  if (user.passwordSalt && user.passwordHash) {
    try {
      const candidate = hashPassword(password, user.passwordSalt);
      return crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(user.passwordHash, 'hex'));
    } catch (_) { return false; }
  }
  // Legacy SHA-256 users remain readable until their password is rotated.
  if (user.password) {
    const candidate = hashPassword(password);
    try { return crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(String(user.password), 'hex')); } catch (_) { return false; }
  }
  return false;
}

// Load users from file
function loadUsers() {
  try {
    if (fs.existsSync(usersFilePath)) {
      return JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));
    }
  } catch (e) {
    logger.error('Failed to load users', e?.message || e);
  }
  return {};
}

// Save users to file
function saveUsers(users) {
  try {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
  } catch (e) {
    logger.error('Failed to save users', e?.message || e);
  }
}

// Load approved keys from approval.txt
function loadApprovedKeys() {
  try {
    if (fs.existsSync(approvalFilePath)) {
      const content = fs.readFileSync(approvalFilePath, 'utf8');
      return content.split('\n').map(line => line.trim()).filter(Boolean);
    }
  } catch (e) {
    logger.error('Failed to load approval keys', e?.message || e);
  }
  return [];
}

// Check if key is approved
function isKeyApproved(key) {
  const approvedKeys = loadApprovedKeys();
  return approvedKeys.includes(key);
}

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    // Never allow a client supplied filename to influence the upload path.
    const safeOriginal = path.basename(String(file.originalname || 'upload'))
      .replace(/[^A-Za-z0-9._-]/g, '_')
      .slice(0, 180) || 'upload';
    cb(null, Date.now() + '_' + crypto.randomBytes(6).toString('hex') + '_' + safeOriginal);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB per file; media is uploaded one file at a time
});

// Bot-hosting panels commonly put the Node app behind a reverse proxy.
// Trust proxy metadata so same-origin checks use the public URL seen by the browser.
app.set('trust proxy', true);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Security headers. Private session/auth files are never served as static files.
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');
  next();
});

// Reject cross-site state-changing requests, while correctly handling reverse-proxy
// deployments (Bot-Hosting/Cloudflare/etc.) where the internal Node host differs
// from the public host shown in the browser.
app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();

  const origin = String(req.headers.origin || '').trim();
  if (!origin) return next();

  const forwardedProto = String(req.headers['x-forwarded-proto'] || '')
    .split(',')[0].trim().toLowerCase();
  const forwardedHost = String(req.headers['x-forwarded-host'] || '')
    .split(',')[0].trim();

  const expectedProtocol = forwardedProto || String(req.protocol || 'http').toLowerCase();
  const expectedHost = forwardedHost || String(req.get('host') || '').trim();
  const expected = `${expectedProtocol}://${expectedHost}`;

  if (origin === expected) return next();

  try {
    const originUrl = new URL(origin);
    const expectedUrl = new URL(expected);
    const normalizePort = (url) => {
      if ((url.protocol === 'https:' && (url.port === '' || url.port === '443')) ||
          (url.protocol === 'http:' && (url.port === '' || url.port === '80'))) return '';
      return url.port;
    };
    if (originUrl.protocol === expectedUrl.protocol &&
        originUrl.hostname === expectedUrl.hostname &&
        normalizePort(originUrl) === normalizePort(expectedUrl)) {
      return next();
    }
  } catch (_) {}

  return res.status(403).json({ ok: false, error: 'Cross-site request blocked' });
});

function parseCookies(req) {
  const out = Object.create(null);
  const raw = String(req.headers.cookie || '');
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

function setAuthCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true';
  const parts = [
    `wa_auth=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=86400'
  ];
  if (secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', 'wa_auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
}

// Security: do NOT expose the server working directory as static web content.
// This prevents direct download of server JS, users.json, auth files, uploaded_sessions,
// CREDS/keys and other private files. The dashboard is served only by the / route below.


const SESSIONS = Object.create(null); // sessionId -> session object
const CREDS_HASH_TO_SESSION = Object.create(null); // credsHash -> sessionId
const AUTH_TOKENS = new Map(); // authToken -> { username, role, createdAt }

// Watcher bookkeeping
const DIR_WATCHERS = Object.create(null);

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function makeSessionId() {
  return 'sess_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 9);
}

function makeSessionDir(sessionId) {
  const dir = path.join(sessionsRoot, sessionId);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanupLegacyRootAuthState(sessionDir) {
  // Current sessions keep Primary/Resume auth in dedicated directories.
  // Older builds also copied creds.json + keys/ into the session root.
  // Those legacy copies are not used when primary/ or resume/ exists and
  // can consume significant disk space over time.
  try {
    if (!sessionDir || !fs.existsSync(sessionDir)) return 0;
    const primaryDir = path.join(sessionDir, 'primary');
    const resumeDir = path.join(sessionDir, 'resume');
    const hasDedicatedAuth = fs.existsSync(primaryDir) || fs.existsSync(resumeDir);
    if (!hasDedicatedAuth) return 0;

    let removed = 0;
    const legacyCreds = path.join(sessionDir, 'creds.json');
    if (fs.existsSync(legacyCreds)) {
      try { fs.unlinkSync(legacyCreds); removed++; } catch (_) {}
    }

    const legacyKeys = path.join(sessionDir, 'keys');
    if (fs.existsSync(legacyKeys)) {
      try { fs.rmSync(legacyKeys, { recursive: true, force: true }); removed++; } catch (_) {}
    }
    return removed;
  } catch (_) {
    return 0;
  }
}

function sleep(ms) {
  const n = Number(ms);
  return new Promise(r => setTimeout(r, Number.isFinite(n) && n >= 0 ? n : 2000));
}

// Browser MediaRecorder commonly produces WebM/Opus on Android/Chrome.
// WhatsApp voice notes are most reliable as OGG/Opus, so Voice Server
// normalizes each recorded clip before it is queued for sending.
function convertVoiceToOggOpus(inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    // Normalize every upload to a conservative WhatsApp PTT format:
    // OGG container + mono Opus + 48 kHz. Never trust the original extension.
    execFile('ffmpeg', [
      '-hide_banner', '-loglevel', 'error', '-y',
      '-i', inputPath,
      '-map', '0:a:0',
      '-vn', '-sn', '-dn',
      '-ac', '1', '-ar', '48000',
      '-c:a', 'libopus', '-b:a', '32k', '-vbr', 'on',
      '-application', 'voip', '-compression_level', '10',
      '-map_metadata', '-1',
      outputPath
    ], { timeout: 120000 }, (error, stdout, stderr) => {
      if (error) {
        const detail = String(stderr || error.message || 'ffmpeg conversion failed').trim();
        reject(new Error(detail));
        return;
      }
      execFile('ffprobe', [
        '-v', 'error', '-select_streams', 'a:0',
        '-show_entries', 'stream=codec_name,codec_type,sample_rate,channels',
        '-of', 'json', outputPath
      ], { timeout: 30000 }, (probeErr, probeOut, probeErrText) => {
        if (probeErr) {
          try { fs.unlinkSync(outputPath); } catch (_) {}
          reject(new Error(String(probeErrText || probeErr.message || 'ffprobe verification failed').trim()));
          return;
        }
        try {
          const data = JSON.parse(probeOut || '{}');
          const stream = data?.streams?.[0];
          if (!stream || stream.codec_name !== 'opus' || stream.codec_type !== 'audio') {
            throw new Error('Converted voice is not a valid Opus audio stream');
          }
        } catch (e) {
          try { fs.unlinkSync(outputPath); } catch (_) {}
          reject(e);
          return;
        }
        resolve(outputPath);
      });
    });
  });
}

function hasYouTubeLink(text) {
  return /https?:\/\/(?:www\.)?(?:youtube\.com\/(?:watch\?v=[^\s&]+|shorts\/[^\s?]+|live\/[^\s?]+|channel\/[^\s?]+|@[^\s?]+)|youtu\.be\/[^\s?&]+)/i.test(String(text || ''));
}

// Defensive numeric helpers. Invalid numeric values can propagate into
// Buffer/WebSocket internals as NaN and crash socket creation.
function safeDelayMs(value, fallback = 5000) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.min(Math.floor(n), 24 * 60 * 60 * 1000);
}

function safeReconnectDelay(value, fallback = 4000) {
  return safeDelayMs(value, fallback);
}

// Logging with colors
function appendSessionLog(sessionId, rawMsg) {
  const time = new Date().toISOString();
  const msg = String(rawMsg || '');
  const s = SESSIONS[sessionId];

  if (s) {
    s.logs = s.logs || [];
    s.logs.push({ time, msg });
    if (s.logs.length > 120) s.logs = s.logs.slice(-120);
  }

  const lower = msg.toLowerCase();
  let kind = 'other';
  if (/(\bsent\b|\bsuccessful\b|\bsuccess\b|\breconnect successful\b|\bstarted\b|\bopen\b|\bcreated\b|\bstarted loop\b)/.test(lower)) {
    kind = 'success';
  } else if (/(\berror\b|\bfailed\b|\bdeleted\b|\blogged out\b|\binvalid\b|\bunauthorized\b|\b401\b|\bdisconnect\b|\bclose\b|\bfailed to\b|\bexpired\b|\bremoved\b)/.test(lower)) {
    kind = 'error';
  } else {
    kind = 'other';
  }

  const timeStr = chalk.yellow(`[${time}]`);
  let symbol = 'i';
  let symbolColored = chalk.cyan(`[${symbol}]`);
  let messageColored = chalk.cyan(msg);

  if (kind === 'success') {
    symbol = '[OK]';
    symbolColored = chalk.greenBright(`[${symbol}]`);
    messageColored = chalk.green(msg);
  } else if (kind === 'error') {
    symbol = '[ERROR]';
    symbolColored = chalk.redBright(`[${symbol}]`);
    messageColored = chalk.red(msg);
  } else {
    symbol = 'i';
    symbolColored = chalk.cyan(`[${symbol}]`);
    messageColored = chalk.cyan(msg);
  }

  const sessionIdStr = sessionId ? chalk.magenta(`[${sessionId}]`) : '';
  const line = `${timeStr} ${symbolColored} ${messageColored} ${sessionIdStr}`;
  console.log(line);
  console.log(chalk.gray('-'.repeat(80)));

  logger.info({ sessionId, kind, time }, msg);
}

// Session metadata save
function persistSessionFiles(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s) return;
  try {
    const sessionMeta = {
      sessionId: s.sessionId,
      username: s.username,
      contacts: s.contacts,
      messages: s.messages,
      prefixName: s.prefixName,
      lastPrefixName: s.lastPrefixName,
      delayMs: s.delayMs,
      target: s.target,
      groupId: s.groupId,
      sessionType: s.sessionType || 'message',
      mentionType: s.mentionType || 'none',
      mentionNumbers: Array.isArray(s.mentionNumbers) ? s.mentionNumbers : [],
      mediaFiles: (s.mediaFiles || []).map(p => path.basename(p)),
      createdAt: s.createdAt || new Date().toISOString(),
      startedAt: s.startedAt || Date.now(),
      credsHash: s.credsHash || null,
      resumeCredsHash: s.resumeCredsHash || null,
      resumeTargetID: s.resumeTargetID || '',
      resumePhone: s.resumePhone || null,
      primaryTargetID: s.primaryTargetID || '',
      primaryPhone: s.primaryPhone || null,
      activeCredentialSlot: s.activeCredentialSlot || 'primary',
      primaryAuthDir: s.primaryAuthDir || 'primary',
      resumeAuthDir: s.resumeAuthDir || 'resume',
      primaryCredsHash: s.primaryCredsHash || null,
      stopped: s.stopped || false,
      voiceIndex: Number.isFinite(Number(s.voiceIndex)) ? Number(s.voiceIndex) : 0,
      voiceCompleted: !!s.voiceCompleted,
      credentialReplacementInProgress: false,
      awaitingCredentials: !!s.awaitingCredentials,
      lastAuthError: s.lastAuthError || null,
      pairingOnly: !!s.pairingOnly,
      // Persist the last known group list so a server/page restart does not
      // temporarily turn a healthy paired account into "Groups (0)".
      groups: Array.isArray(s.groups) ? s.groups : []
    };
    fs.writeFileSync(path.join(s.sessionDir, 'session.json'), JSON.stringify(sessionMeta, null, 2), 'utf8');
    fs.writeFileSync(path.join(s.sessionDir, 'messages.txt'), (s.messages || []).join('\n'), 'utf8');
  } catch (e) {
    appendSessionLog(sessionId, 'persistSessionFiles error: ' + (e?.message || e));
  }
}

// Enhanced prune helper
function pruneAuthFiles(sessionDir, sessionId = null) {
  // Keep the complete multi-file Baileys auth/key state.
  // Do not automatically delete pre-keys, sender-keys or session keys.
  return 0;
}

// Start file-system watchers
function startSessionWatch(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s) return;
  const sessionDir = s.sessionDir;
  if (!sessionDir || !fs.existsSync(sessionDir)) return;

  if (DIR_WATCHERS[sessionId]) return;

  const watchers = { dirWatcher: null, keysWatcher: null, debounceTimer: null, groupFailoverTimer: null, groupFailoverBusy: false };

  const schedulePrune = () => {
    if (watchers.debounceTimer) clearTimeout(watchers.debounceTimer);
    watchers.debounceTimer = setTimeout(() => {
      try {
        const removed = pruneAuthFiles(sessionDir, sessionId);
        if (removed && removed > 0) {
          logger.debug && logger.debug({ sessionId, removed }, 'Pruned auth files after fs event');
        }
      } catch (e) {}
      watchers.debounceTimer = null;
    }, PRUNE_DEBOUNCE_MS);
  };

  try {
    watchers.dirWatcher = fs.watch(sessionDir, (eventType, filename) => {
      if (!filename) return;
      // Ignore changes inside media/ subfolder
      if (String(filename).startsWith('media')) return;
      schedulePrune();
    });
  } catch (e) {}

  try {
    const keysDir = path.join(sessionDir, 'keys');
    if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { recursive: true });
    watchers.keysWatcher = fs.watch(keysDir, (eventType, filename) => {
      if (!filename) return;
      schedulePrune();
    });
  } catch (e) {}

  DIR_WATCHERS[sessionId] = watchers;

  // Keep the Primary <-> Resume failover state automatic for group sessions.
  // This is intentionally independent of the sender loop, so changing the
  // media type/editing a running process cannot remove or duplicate failover.
  if (s.target === 'gc' && s.resumeEnabled) {
    watchers.groupFailoverTimer = setInterval(() => {
      if (watchers.groupFailoverBusy) return;
      watchers.groupFailoverBusy = true;
      checkGroupFailover(sessionId)
        .catch(err => appendSessionLog(sessionId, '[FAILOVER] Group monitor error: ' + (err?.message || err)))
        .finally(() => { watchers.groupFailoverBusy = false; });
    }, 15000);
    // Run one check shortly after startup instead of waiting a full interval.
    setTimeout(() => {
      if (!DIR_WATCHERS[sessionId]) return;
      if (watchers.groupFailoverBusy) return;
      watchers.groupFailoverBusy = true;
      checkGroupFailover(sessionId)
        .catch(err => appendSessionLog(sessionId, '[FAILOVER] Group monitor error: ' + (err?.message || err)))
        .finally(() => { watchers.groupFailoverBusy = false; });
    }, 3000);
  }
}

// Stop watchers
function stopSessionWatch(sessionId) {
  const w = DIR_WATCHERS[sessionId];
  if (!w) return;
  try { if (w.dirWatcher) w.dirWatcher.close(); } catch (e) {}
  try { if (w.keysWatcher) w.keysWatcher.close(); } catch (e) {}
  try { if (w.debounceTimer) clearTimeout(w.debounceTimer); } catch (e) {}
  try { if (w.groupFailoverTimer) clearInterval(w.groupFailoverTimer); } catch (e) {}
  delete DIR_WATCHERS[sessionId];
}

// Complete session cleanup (delete all files and folder)
function completeSessionCleanup(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s || !s.sessionDir) return;

  try {
    appendSessionLog(sessionId, '[CLEANUP] Complete cleanup: removing session folder');

    // Stop watchers first
    stopSessionWatch(sessionId);

    // Remove entire session directory
    if (fs.existsSync(s.sessionDir)) {
      fs.rmSync(s.sessionDir, { recursive: true, force: true });
      appendSessionLog(sessionId, '[OK] Session folder completely removed');
    }

    // Remove from memory
    if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash]) delete CREDS_HASH_TO_SESSION[s.credsHash];
    if (s.resumeCredsHash && CREDS_HASH_TO_SESSION[s.resumeCredsHash]) delete CREDS_HASH_TO_SESSION[s.resumeCredsHash];
    delete SESSIONS[sessionId];

  } catch (e) {
    appendSessionLog(sessionId, '[ERROR] Cleanup error: ' + (e?.message || e));
  }
}

// Cleanup only temporary session files. NEVER delete WhatsApp auth state.
// Primary and Resume each contain their own creds.json + Baileys key state;
// deleting keys/ can invalidate an otherwise healthy WhatsApp session.
function cleanupSessionFiles(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s || !s.sessionDir) return;

  const PROTECTED_FILES = ['session.json', 'messages.txt', 'creds.json'];
  const PROTECTED_DIRS = ['keys', s.primaryAuthDir || 'primary', s.resumeAuthDir || 'resume'];
  let deletedCount = 0;

  try {
    appendSessionLog(sessionId, '[CLEANUP] Starting cleanup of temporary session files; WhatsApp auth state will be preserved...');

    const files = fs.readdirSync(s.sessionDir, { withFileTypes: true });
    for (const file of files) {
      if (file.isFile() && !PROTECTED_FILES.includes(file.name)) {
        try {
          fs.unlinkSync(path.join(s.sessionDir, file.name));
          deletedCount++;
        } catch (e) {}
      }
    }

    // IMPORTANT: Do not remove keys/, primary/, or resume/.
    // These directories contain the complete Baileys authentication state.
    for (const dirName of PROTECTED_DIRS) {
      if (dirName && fs.existsSync(path.join(s.sessionDir, dirName))) {
        appendSessionLog(sessionId, `[OK] Preserved WhatsApp auth directory: ${dirName}/`);
      }
    }

    // Media is disposable and does not contain WhatsApp authentication state.
    const mediaDir = path.join(s.sessionDir, 'media');
    if (fs.existsSync(mediaDir)) {
      try {
        fs.rmSync(mediaDir, { recursive: true, force: true });
        appendSessionLog(sessionId, '[OK] Deleted disposable media/ subdirectory');
      } catch (e) {}
    }

    appendSessionLog(sessionId, `[OK] Cleanup complete: ${deletedCount} temporary files deleted; auth state preserved`);
  } catch (e) {
    appendSessionLog(sessionId, '[ERROR] Cleanup error: ' + (e?.message || e));
  }
}

// Check if credentials are invalid/logged out/expired - FIXED VERSION
function isLoggedOutUpdate(update) {
  const last = update?.lastDisconnect;
  if (!last) return false;

  const error = last.error;
  const statusCode = error?.output?.statusCode;
  const msg = (error && (error.message || String(error))) || String(error || '');

  if (!msg && !statusCode) return false;

  const lower = msg.toLowerCase();

  const actualLoggedOutPatterns = [
    'logged out',
    'logged-out',
    'device not found',
    'invalid mac',
    'qr refs attempts ended',
    'restart required'
  ];

  if (statusCode === 401) {
    appendSessionLog(null, `Detected auth failure with status code: ${statusCode}`);
    return true;
  }

  for (const pattern of actualLoggedOutPatterns) {
    if (lower.includes(pattern)) {
      appendSessionLog(null, `Detected logged out pattern: "${pattern}" in message: "${msg}"`);
      return true;
    }
  }

  return false;
}

// Check if creds are actually logged in to WhatsApp
async function checkIfLoggedIn(sock, sessionId, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    let resolved = false;
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        reject(new Error('Timeout: Failed to verify login status'));
      }
    }, timeoutMs);

    const connectionHandler = (update) => {
      if (resolved) return;

      const { connection, lastDisconnect } = update;

      if (connection === 'open') {
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          sock.ev.off('connection.update', connectionHandler);
          resolve(true);
        }
        return;
      }

      if (connection === 'close') {
        if (isLoggedOutUpdate(update)) {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeout);
            sock.ev.off('connection.update', connectionHandler);
            const errorMsg = lastDisconnect?.error?.message || 'Credentials expired or logged out';
            reject(new Error(errorMsg));
          }
        }
      }
    };

    sock.ev.on('connection.update', connectionHandler);
  });
}

// Extract the WhatsApp account phone number from Baileys creds.json or a socket user JID.
function extractWhatsAppPhoneFromCreds(filePath) {
  try {
    const json = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const raw = json?.me?.id || json?.me?.jid || json?.me?.phoneNumber || '';
    const match = String(raw).match(/(\d{7,15})/);
    return match ? match[1] : null;
  } catch (e) {
    return null;
  }
}

function extractWhatsAppPhoneFromSession(s) {
  try {
    const raw = s?.phone || s?.phoneNumber || s?.sock?.user?.id || s?.sock?.user?.jid || '';
    const match = String(raw).match(/(\d{7,15})/);
    return match ? match[1] : null;
  } catch (e) {
    return null;
  }
}

// Validate creds.json structure
function validateCredsJson(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const json = JSON.parse(content);

    if (!json.noiseKey || !json.signedIdentityKey || !json.signedPreKey) {
      return false;
    }

    return true;
  } catch (e) {
    return false;
  }
}

// Helper: rebuild full media file paths from session dir
function loadMediaFiles(sessionDir) {
  const mediaDir = path.join(sessionDir, 'media');
  if (!fs.existsSync(mediaDir)) return [];
  try {
    return fs.readdirSync(mediaDir)
      .filter(f => !f.startsWith('.'))
      .map(f => path.join(mediaDir, f))
      .filter(f => {
        try { return fs.statSync(f).isFile(); } catch (e) { return false; }
      })
      .sort();
  } catch (e) {
    return [];
  }
}

function getActiveAuthDir(s) {
  if (!s || !s.sessionDir) return null;
  const slot = s.activeCredentialSlot === 'resume' ? (s.resumeAuthDir || 'resume') : (s.primaryAuthDir || 'primary');
  const preferred = path.join(s.sessionDir, slot);
  if (fs.existsSync(path.join(preferred, 'creds.json'))) return preferred;

  // Never fall back to the legacy session-root creds.json when dedicated
  // primary/resume auth directories exist. That root copy can be stale and
  // cause a reconnect to load the wrong WhatsApp identity.
  const legacyRootCreds = path.join(s.sessionDir, 'creds.json');
  const primaryDir = path.join(s.sessionDir, s.primaryAuthDir || 'primary');
  const resumeDir = path.join(s.sessionDir, s.resumeAuthDir || 'resume');
  const hasDedicatedDirs = fs.existsSync(primaryDir) || fs.existsSync(resumeDir);
  if (!hasDedicatedDirs && fs.existsSync(legacyRootCreds)) return s.sessionDir;
  return preferred;
}

function normalizeTargetData(type, targetID) {
  const normalizedType = String(type || '').toLowerCase() === 'gc' ? 'gc' : 'ib';
  const raw = String(targetID || '').trim();
  if (normalizedType === 'gc') {
    if (!raw) throw new Error('Group ID is required');
    return { target: 'gc', groupId: raw, contacts: [raw] };
  }
  const contacts = raw.split(/[\r\n,]+/)
    .map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, ''))
    .filter(Boolean);
  if (!contacts.length) throw new Error('At least one contact number is required');
  return { target: 'ib', groupId: null, contacts };
}

// Restart a session
async function restartSession(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s) {
    appendSessionLog(sessionId, 'restartSession: no in-memory session found');
    return;
  }

  if (s.stopped) {
    appendSessionLog(sessionId, 'Session was manually stopped - will not restart');
    return;
  }

  if (s.restartLock) {
    appendSessionLog(sessionId, 'Restart already in progress, skipping duplicate restart.');
    return;
  }
  s.restartLock = true;

  const dir = s.sessionDir;
  if (!dir || !fs.existsSync(dir)) {
    appendSessionLog(sessionId, 'restartSession: session folder missing, cannot restart');
    s.restartLock = false;
    return;
  }

  appendSessionLog(sessionId, 'Restarting session from disk: ' + dir);

  try {
    const sessionJsonPath = path.join(dir, 'session.json');
    if (fs.existsSync(sessionJsonPath)) {
      const meta = JSON.parse(fs.readFileSync(sessionJsonPath, 'utf8'));
      s.contacts = meta.contacts || s.contacts;
      s.messages = meta.messages || s.messages;
      s.prefixName = (meta.prefixName !== undefined) ? String(meta.prefixName || '').trim() : String(s.prefixName || '').trim();
      s.lastPrefixName = (meta.lastPrefixName !== undefined) ? String(meta.lastPrefixName || '').trim() : String(s.lastPrefixName || '').trim();
      s.delayMs = safeDelayMs(meta.delayMs, safeDelayMs(s.delayMs, 5000));
      s.target = meta.target || s.target;
      s.groupId = meta.groupId || s.groupId;
      s.createdAt = meta.createdAt || s.createdAt;
      s.startedAt = meta.startedAt || s.startedAt || Date.now();
      s.credsHash = meta.credsHash || s.credsHash;
      s.awaitingCredentials = !!meta.awaitingCredentials;
      s.lastAuthError = meta.lastAuthError || null;
      s.username = meta.username || s.username;
      s.stopped = meta.stopped || false;
      s.voiceIndex = Number.isFinite(Number(meta.voiceIndex)) ? Number(meta.voiceIndex) : 0;
      s.voiceCompleted = !!meta.voiceCompleted;
      s.sessionType = meta.sessionType || s.sessionType || 'message';
      s.mentionType = meta.mentionType || s.mentionType || 'none';
      s.mentionNumbers = Array.isArray(meta.mentionNumbers) ? meta.mentionNumbers : (s.mentionNumbers || []);
      s.mediaFiles = loadMediaFiles(dir);
      if (s.credsHash) CREDS_HASH_TO_SESSION[s.credsHash] = sessionId;
    }
  } catch (e) {
    appendSessionLog(sessionId, 'Failed to read session.json during restart: ' + (e?.message || e));
  }

  s.runningLoop = false;
  s.reconnectAttempts = 0;
  s.firstReconnectTime = null;

  try {
    s.sock = null;
    const activeAuthDir = getActiveAuthDir(s);
    s.sock = await createOrGetSocket(activeAuthDir || dir, sessionId);
    appendSessionLog(sessionId, '[OK] Session restarted successfully');

    try {
      await startSendingLoop(sessionId);
      appendSessionLog(sessionId, 'Session restarted and sending loop started');
    } catch (e) {
      appendSessionLog(sessionId, 'restart startSendingLoop failed: ' + (e?.message || e));
    }
  } catch (e) {
    appendSessionLog(sessionId, 'Restart: socket creation failed: ' + (e?.message || e));
  } finally {
    s.restartLock = false;
  }
}

// Attempt reconnect with 1-hour timeout
async function attemptReconnect(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s || s.stopped || s.awaitingCredentials) return;

  if (s.reconnectLock || s.restartLock) {
    appendSessionLog(sessionId, 'Reconnect/restart already in progress, skipping duplicate call');
    return;
  }

  s.reconnectLock = true;
  s.reconnectAttempts = s.reconnectAttempts || 0;
  const reconnectGeneration = Number(s.reconnectGeneration || 0);

  let delayMs = RECONNECT_DELAY_MS;

  try {
    while (SESSIONS[sessionId] && !s.stopped && !s.awaitingCredentials) {
      const reconnectSlot = s.activeCredentialSlot || 'primary';
      const reconnectStartGeneration = Number(s.reconnectGeneration || 0);
      s.reconnectAttempts++;

      appendSessionLog(
        sessionId,
        `Reconnect attempt ${s.reconnectAttempts} (waiting ${delayMs}ms)`
      );

      await sleep(delayMs);

      // A failover changed the active credential slot while this reconnect was
      // sleeping. Cancel this stale reconnect completely; otherwise the old
      // Primary socket can come back while Resume is already active (causing
      // WhatsApp Stream Errored (conflict)).
      if (!SESSIONS[sessionId] || s.stopped || s.awaitingCredentials) break;
      if ((s.activeCredentialSlot || 'primary') !== reconnectSlot ||
          Number(s.reconnectGeneration || 0) !== reconnectStartGeneration ||
          reconnectGeneration !== Number(s.reconnectGeneration || 0)) {
        break;
      }

      try {
        // Reconnect using the currently active credential slot only.
        // Loading the session root here could reopen a stale legacy creds.json
        // and make a Primary/Resume edit look like an unexpected logout.
        const activeAuthDir = getActiveAuthDir(s) || s.sessionDir;
        const newSock = await createOrGetSocket(activeAuthDir, sessionId, reconnectSlot);

        if (newSock) {
          if ((s.activeCredentialSlot || 'primary') !== reconnectSlot ||
              Number(s.reconnectGeneration || 0) !== reconnectStartGeneration ||
              s.stopped || s.awaitingCredentials) {
            try { newSock.__dkRetired = true; newSock?.ws?.close?.(); newSock?.socket?.close?.(); newSock?.end?.(); } catch (_) {}
            break;
          }
          s.sock = newSock;
          s.reconnectAttempts = 0;
          s.firstReconnectTime = null;
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, '[OK] Reconnect successful - Socket recreated');
          return;
        }
      } catch (e) {
        const errorMsg = String(e?.message || e);
        appendSessionLog(sessionId, 'Reconnect try failed: ' + errorMsg);

        const lower = errorMsg.toLowerCase();
        if (
          lower.includes('logged out') ||
          lower.includes('invalid mac') ||
          lower.includes('device not found') ||
          lower.includes('qr refs attempts ended')
        ) {
          s.awaitingCredentials = true;
          s.lastAuthError = errorMsg;
          s.reconnectAttempts = 0;
          s.firstReconnectTime = null;
          persistSessionFiles(sessionId);
          appendSessionLog(
            sessionId,
            'Authentication expired/logged out. Session preserved; waiting for new creds.json.'
          );
          return;
        }
      }

      // Never give up because of an arbitrary attempt count or one-hour timer.
      // Increase delay gradually, max 60 seconds, then keep retrying.
      delayMs = Math.min(Math.max(RECONNECT_DELAY_MS, delayMs * 2), 60000);
    }
  } finally {
    s.reconnectLock = false;
  }
}

// Restore sessions from disk
function restoreSessionsFromDisk() {
  const entries = fs.existsSync(sessionsRoot) ? fs.readdirSync(sessionsRoot, { withFileTypes: true }) : [];
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const sessionId = e.name;
    const dir = path.join(sessionsRoot, sessionId);
    const sessionJsonPath = path.join(dir, 'session.json');
    const credsPath = path.join(dir, 'creds.json');

    if (fs.existsSync(sessionJsonPath)) {
      try {
        if (!validateCredsJson(credsPath)) {
          appendSessionLog(sessionId, 'Invalid creds.json format detected. Session kept for replacement credentials.');
        }

        const meta = JSON.parse(fs.readFileSync(sessionJsonPath, 'utf8'));

        if (meta.stopped) {
          appendSessionLog(sessionId, 'Session was stopped - skipping restore');
          continue;
        }

        const sess = {
          sessionId: meta.sessionId || sessionId,
          sessionDir: dir,
          username: meta.username || 'unknown',
          phone: meta.phone || null,
          resumeTargetID: meta.resumeTargetID || '',
          resumePhone: meta.resumePhone || null,
          primaryTargetID: meta.primaryTargetID || (meta.target === 'gc' ? (meta.groupId || '') : ''),
          primaryPhone: meta.primaryPhone || meta.phone || null,
          resumeEnabled: !!(meta.resumeEnabled || meta.resumeCredsHash || meta.resumePhone),
          activeCredentialSlot: meta.activeCredentialSlot === 'backup' ? 'resume' : (meta.activeCredentialSlot || 'primary'),
          primaryAuthDir: meta.primaryAuthDir || 'primary',
          resumeAuthDir: meta.resumeAuthDir || 'resume',
          credsHash: meta.credsHash || null,
          primaryCredsHash: meta.primaryCredsHash || meta.credsHash || null,
          resumeCredsHash: meta.resumeCredsHash || null,
          contacts: meta.contacts || [],
          messages: meta.messages || [],
          prefixName: meta.prefixName || '',
          lastPrefixName: meta.lastPrefixName || '',
          delayMs: safeDelayMs(meta.delayMs, 5000),
          runningLoop: false,
          sock: null,
          target: meta.target || 'contacts',
          groupId: meta.groupId || null,
          sessionType: meta.sessionType || 'message',
          mentionType: meta.mentionType || 'none',
          mentionNumbers: Array.isArray(meta.mentionNumbers) ? meta.mentionNumbers : [],
          mediaFiles: loadMediaFiles(dir),
          logs: [],
          awaitingCredentials: !!meta.awaitingCredentials,
          lastAuthError: meta.lastAuthError || null,
          pairingOnly: !!meta.pairingOnly,
          groups: Array.isArray(meta.groups) ? meta.groups : [],
          createdAt: meta.createdAt || new Date().toISOString(),
          startedAt: meta.startedAt || Date.now(),
          lastAuthError: meta.lastAuthError || null,
          reconnectAttempts: 0,
          reconnectLock: false,
          restartLock: false,
          failoverLock: false,
          credentialReplacementInProgress: false,
          firstReconnectTime: null,
          deleting: false,
          stopped: !!meta.stopped
        };

        SESSIONS[sess.sessionId] = sess;

        // Only reserve credentials for a session that is actually active.
        // A manually stopped/terminated session must not leave a stale
        // duplicate-credentials lock after a server restart.
        if (!sess.stopped && !sess.awaitingCredentials) {
          try {
            const activeDir = getActiveAuthDir(sess);
            const activeCredsPath = activeDir ? path.join(activeDir, 'creds.json') : credsPath;
            if (fs.existsSync(activeCredsPath)) {
              const hash = sha256File(activeCredsPath);
              sess.credsHash = hash;
              CREDS_HASH_TO_SESSION[hash] = sess.sessionId;
            }
          } catch (e) {}
        }

        const restoredAuthDir = getActiveAuthDir(sess);
        if (!restoredAuthDir || !validateCredsJson(path.join(restoredAuthDir, 'creds.json'))) {
          sess.awaitingCredentials = true;
          sess.lastAuthError = sess.lastAuthError || 'No valid active creds.json found';
          persistSessionFiles(sess.sessionId);
        }

        appendSessionLog(sess.sessionId, `Restored session from disk (type=${sess.sessionType}, media=${sess.mediaFiles.length}), ${sess.awaitingCredentials ? 'waiting for credentials' : 'reconnecting'}...`);

        try { startSessionWatch(sess.sessionId); } catch (e) {}

        (async () => {
          if (SESSIONS[sess.sessionId].awaitingCredentials) {
            appendSessionLog(sess.sessionId, 'Session restored and waiting for valid creds.json; uptime preserved.');
            return;
          }
          try {
            const activeAuthDir = sess.activeCredentialSlot === 'resume' && fs.existsSync(path.join(sess.sessionDir, sess.resumeAuthDir || 'resume', 'creds.json'))
              ? path.join(sess.sessionDir, sess.resumeAuthDir || 'resume')
              : (fs.existsSync(path.join(sess.sessionDir, sess.primaryAuthDir || 'primary', 'creds.json'))
                ? path.join(sess.sessionDir, sess.primaryAuthDir || 'primary')
                : sess.sessionDir);
            SESSIONS[sess.sessionId].sock = await createOrGetSocket(activeAuthDir, sess.sessionId);
            appendSessionLog(sess.sessionId, '[OK] Socket created successfully on restore');
          } catch (e) {
            appendSessionLog(sess.sessionId, 'Socket create failed on restore: ' + (e?.message || e));
            return;
          }

          if (sess.pairingOnly) {
            appendSessionLog(sess.sessionId, `[PAIRING] Paired account restored; sender loop remains disabled. Use the Groups panel to select a group.`);
            try {
              const restoredGroups = await getParticipatingGroups(SESSIONS[sess.sessionId].sock);
              if (Array.isArray(restoredGroups)) sess.groups = restoredGroups;
            } catch (_) {
              // Keep the groups restored from session.json if WhatsApp is
              // temporarily unavailable during server startup.
            }
            persistSessionFiles(sess.sessionId);
            return;
          }
          try {
            await startSendingLoop(sess.sessionId);
          } catch (err) {
            appendSessionLog(sess.sessionId, 'startSendingLoop on restore failed: ' + (err?.message || err));
          }
        })();
      } catch (err) {
        logger.warn('Failed to restore session', sessionId, err?.message || err);
      }
    }
  }
}

// Switch an authorized session from primary credentials to its configured resume credentials.
// Session ID and startedAt are intentionally preserved. This does not bypass a WhatsApp suspension;
// it only activates a separately supplied, valid backup session when the primary disconnects.
async function switchToResumeCredentials(sessionId, reason = 'Primary credentials logged out/expired') {
  const s = SESSIONS[sessionId];
  if (!s || s.stopped) return false;
  if (s.activeCredentialSlot === 'resume') return true;
  if (s.failoverLock) return false;

  const resumeDir = path.join(s.sessionDir, s.resumeAuthDir || 'resume');
  const resumeCreds = path.join(resumeDir, 'creds.json');
  if (!validateCredsJson(resumeCreds)) {
    throw new Error('Resume credentials are missing or invalid');
  }

  s.failoverLock = true;
  s.reconnectGeneration = Number(s.reconnectGeneration || 0) + 1;
  const oldSock = s.sock;

  try {
    // Keep Primary assigned until Resume is actually OPEN. This prevents a
    // transient Resume failure from leaving a healthy Primary session stopped.
    appendSessionLog(sessionId, `[FAILOVER] ${reason}. Resume credentials are being activated...`);

    const newSock = await createOrGetSocket(resumeDir, sessionId, 'resume');
    if (!newSock) throw new Error('Failed to create Resume socket');

    if (SESSIONS[sessionId] !== s || s.stopped) {
      try {
        if (newSock?.ws?.close) newSock.ws.close();
        else if (newSock?.socket?.close) newSock.socket.close();
        else if (newSock?.end) newSock.end();
      } catch (_) {}
      return false;
    }

    const resumeSocketReady = await waitForSocketObjectOpen(newSock, 60000);
    if (!resumeSocketReady) {
      appendSessionLog(sessionId, '[FAILOVER] Resume socket did not reach OPEN; Primary remains active.');
      try {
        if (newSock?.ws?.close) newSock.ws.close();
        else if (newSock?.socket?.close) newSock.socket.close();
        else if (newSock?.end) newSock.end();
      } catch (_) {}
      return false;
    }

    // Resume is ready: now atomically move the session to Resume target/creds.
    s.activeCredentialSlot = 'resume';
    s.awaitingCredentials = false;
    s.reconnectGeneration = Number(s.reconnectGeneration || 0) + 1;
    s.lastAuthError = null;
    s.reconnectAttempts = 0;
    s.firstReconnectTime = null;
    s.reconnectLock = false;
    s.phone = s.resumePhone || extractWhatsAppPhoneFromCreds(resumeCreds);

    if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash] === sessionId) {
      delete CREDS_HASH_TO_SESSION[s.credsHash];
    }
    s.credsHash = s.resumeCredsHash || sha256File(resumeCreds);

    const resumeTarget = String(s.resumeTargetID || '').trim() ||
      (s.target === 'gc' ? String(s.groupId || '').trim() : (s.contacts || []).join(','));

    if (s.target === 'gc') {
      s.groupId = resumeTarget;
      s.contacts = [resumeTarget];
    } else {
      s.contacts = resumeTarget.split(/[,\r\n]+/)
        .map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, ''))
        .filter(Boolean);
    }

    s.sock = newSock;
    CREDS_HASH_TO_SESSION[s.credsHash] = sessionId;
    persistSessionFiles(sessionId);

    // Only close Primary after Resume has been proven open and installed.
    if (oldSock && oldSock !== newSock) {
      oldSock.__dkRetired = true;
      try {
        if (oldSock?.ws?.close) oldSock.ws.close();
        else if (oldSock?.socket?.close) oldSock.socket.close();
        else if (oldSock?.end) oldSock.end();
      } catch (_) {}
    }

    appendSessionLog(
      sessionId,
      `[FAILOVER] Resume credentials active: ${s.phone || 'unknown phone'} / Target ${s.resumeTargetID || 'unknown'}`
    );
    appendSessionLog(sessionId, '[FAILOVER] Resume socket ready; existing sending loop continues on the same delay schedule');
    return true;
  } finally {
    s.failoverLock = false;
    if (s.activeCredentialSlot === 'primary' && !s.sock && !s.stopped && !s.awaitingCredentials) {
      attemptReconnect(sessionId).catch(e => appendSessionLog(sessionId, '[FAILOVER] Primary recovery reconnect failed: ' + (e?.message || e)));
    }
  }
}

// Switch an authorized session from Resume credentials back to its Primary
// credentials after the primary group is healthy again.
async function switchToPrimaryCredentials(sessionId, reason = 'Primary group is normal again', existingSock = null) {
  const s = SESSIONS[sessionId];
  if (!s || s.stopped) return false;
  if (s.activeCredentialSlot === 'primary') return true;
  if (s.failoverLock) return false;

  const primaryDir = path.join(s.sessionDir, s.primaryAuthDir || 'primary');
  const primaryCreds = path.join(primaryDir, 'creds.json');
  if (!validateCredsJson(primaryCreds)) return false;

  s.failoverLock = true;
  s.reconnectGeneration = Number(s.reconnectGeneration || 0) + 1;
  const oldSock = s.sock;

  try {
    // Keep Resume assigned until Primary is actually OPEN. This prevents a
    // healthy Resume session from being left without a socket if Primary fails.
    appendSessionLog(sessionId, `[FAILOVER] ${reason}. Testing Primary credentials...`);

    const newSock = existingSock || await createOrGetSocket(primaryDir, sessionId, 'primary');
    if (!newSock) throw new Error('Failed to create Primary socket');

    if (SESSIONS[sessionId] !== s || s.stopped) {
      try {
        if (newSock?.ws?.close) newSock.ws.close();
        else if (newSock?.socket?.close) newSock.socket.close();
        else if (newSock?.end) newSock.end();
      } catch (_) {}
      return false;
    }

    const ready = await waitForSocketObjectOpen(newSock, 30000);
    if (!ready) {
      try {
        if (newSock?.ws?.close) newSock.ws.close();
        else if (newSock?.socket?.close) newSock.socket.close();
        else if (newSock?.end) newSock.end();
      } catch (_) {}
      appendSessionLog(sessionId, '[FAILOVER] Primary socket did not reach OPEN; Resume remains active.');
      return false;
    }

    // Restore the original Primary target/phone. Resume may use a different
    // target, so never reuse the active Resume target when switching back.
    newSock.__dkSocketRole = 'primary';
    newSock.__dkRetired = false;
    const primaryTarget = String(s.primaryTargetID || '').trim();
    s.activeCredentialSlot = 'primary';
    s.awaitingCredentials = false;
    s.reconnectGeneration = Number(s.reconnectGeneration || 0) + 1;
    s.lastAuthError = null;
    s.reconnectAttempts = 0;
    s.firstReconnectTime = null;
    s.reconnectLock = false;
    s.phone = s.primaryPhone || extractWhatsAppPhoneFromCreds(primaryCreds);

    if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash] === sessionId) {
      delete CREDS_HASH_TO_SESSION[s.credsHash];
    }
    s.credsHash = s.primaryCredsHash || sha256File(primaryCreds);

    if (s.target === 'gc') {
      const group = primaryTarget || String(s.groupId || '').trim();
      if (group) {
        s.groupId = group;
        s.contacts = [group];
      }
    } else if (primaryTarget) {
      s.contacts = primaryTarget.split(/[,\r\n]+/)
        .map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, ''))
        .filter(Boolean);
    }

    s.sock = newSock;
    CREDS_HASH_TO_SESSION[s.credsHash] = sessionId;
    persistSessionFiles(sessionId);

    // Only close Resume after Primary has been proven open and installed.
    if (oldSock && oldSock !== newSock) {
      oldSock.__dkRetired = true;
      try {
        if (oldSock?.ws?.close) oldSock.ws.close();
        else if (oldSock?.socket?.close) oldSock.socket.close();
        else if (oldSock?.end) oldSock.end();
      } catch (_) {}
    }

    appendSessionLog(
      sessionId,
      `[FAILOVER] Primary credentials active: ${s.phone || 'unknown phone'} / Target ${s.primaryTargetID || s.groupId || 'unknown'}`
    );
    appendSessionLog(sessionId, '[FAILOVER] Primary socket ready; existing sending loop continues on the same delay schedule');
    return true;
  } catch (e) {
    appendSessionLog(sessionId, '[FAILOVER] Primary recovery failed; Resume remains active: ' + (e?.message || e));
    return false;
  } finally {
    s.failoverLock = false;
    if (s.activeCredentialSlot === 'resume' && !s.sock && !s.stopped && !s.awaitingCredentials) {
      attemptReconnect(sessionId).catch(e => appendSessionLog(sessionId, '[FAILOVER] Resume recovery reconnect failed: ' + (e?.message || e)));
    }
  }
}

function isGroupRestrictedOrSuspendedError(error) {
  const status = Number(
    error?.output?.statusCode ??
    error?.statusCode ??
    error?.data?.statusCode ??
    error?.status
  );
  const msg = String(error?.message || error?.output?.payload?.message || error || '').toLowerCase();

  // Do not treat ordinary network timeouts as a group suspension/restriction.
  if (/timeout|timed out|network|econn|socket|connection closed|connection reset/.test(msg)) return false;

  return [401, 403, 406, 410, 419].includes(status) ||
    /no whatsapp acknowledgement received for primary group message/.test(msg) ||
    /group.*(suspend|forbidden|unavailable|removed|revoked)|suspend.*group|forbidden|not.?authorized|access denied|not allowed/.test(msg);
}

async function waitForSocketObjectOpen(sock, timeoutMs = 60000) {
  if (!sock) throw new Error('Socket unavailable');
  if (sock.__dkConnectionOpen === true || sock?.ws?.readyState === 1) return true;

  return new Promise((resolve) => {
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.ev?.off?.('connection.update', handler); } catch (_) {}
      resolve(ok);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    const handler = (update) => {
      if (update?.connection === 'open') {
        sock.__dkConnectionOpen = true;
        finish(true);
      } else if (update?.connection === 'close') {
        finish(false);
      }
    };
    try {
      sock.ev?.on?.('connection.update', handler);
    } catch (_) {
      finish(false);
    }
  });
}

async function checkGroupFailover(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s || s.stopped || s.deleting || s.target !== 'gc' || !s.resumeEnabled) return;

  const groupId = String(
    s.activeCredentialSlot === 'resume'
      ? (s.resumeTargetID || s.groupId || '')
      : (s.primaryTargetID || s.groupId || '')
  ).trim();
  if (!groupId) return;

  const jid = groupId.endsWith('@g.us') ? groupId : `${groupId}@g.us`;

  // PRIMARY -> RESUME:
  // - Group Only Admin (announce=true)
  // - Group suspended/unavailable/forbidden according to group metadata error
  if (s.activeCredentialSlot === 'primary') {
    if (!s.sock || s.sock.__dkConnectionOpen !== true) return;

    try {
      const metadata = await s.sock.groupMetadata(jid);
      if (metadata?.announce === true || metadata?.onlyAdmins === true || metadata?.onlyAdmin === true) {
        appendSessionLog(sessionId, '[FAILOVER] Group is currently Only Admin. Switching Primary -> Resume.');
        await switchToResumeCredentials(sessionId, 'Group Only Admin restriction detected');
      } else if (metadata?.suspended === true || metadata?.isSuspended === true) {
        appendSessionLog(sessionId, '[FAILOVER] Group is marked suspended. Switching Primary -> Resume.');
        await switchToResumeCredentials(sessionId, 'Group suspended status detected');
      }
      return;
    } catch (e) {
      if (isGroupRestrictedOrSuspendedError(e)) {
        appendSessionLog(sessionId, '[FAILOVER] Group is suspended/restricted or unavailable. Switching Primary -> Resume.');
        await switchToResumeCredentials(sessionId, 'Group suspended/restricted detected');
      }
      return;
    }
  }

  // RESUME -> PRIMARY:
  // Probe the original Primary credentials against the original Primary group.
  // Only switch back when Primary is authenticated AND the group is no longer
  // Only Admin/suspended/restricted.
  if (s.activeCredentialSlot === 'resume') {
    const primaryDir = path.join(s.sessionDir, s.primaryAuthDir || 'primary');
    const primaryCreds = path.join(primaryDir, 'creds.json');
    if (!validateCredsJson(primaryCreds)) return;

    let probeSock = null;
    try {
      probeSock = await createOrGetSocket(primaryDir, sessionId, 'primary-probe');
      if (!probeSock) return;

      const ready = await waitForSocketObjectOpen(probeSock, 15000);
      if (!ready) return;

      const primaryGroup = String(s.primaryTargetID || '').trim();
      if (!primaryGroup) return;
      const primaryJid = primaryGroup.endsWith('@g.us') ? primaryGroup : `${primaryGroup}@g.us`;

      const metadata = await probeSock.groupMetadata(primaryJid);
      if (metadata?.announce === true || metadata?.onlyAdmins === true || metadata?.onlyAdmin === true ||
          metadata?.suspended === true || metadata?.isSuspended === true) {
        return; // Primary is still restricted/suspended.
      }

      appendSessionLog(sessionId, '[FAILOVER] Primary group is normal again. Switching Resume -> Primary.');
      const promoted = await switchToPrimaryCredentials(sessionId, 'Primary group returned to normal', probeSock);
      if (promoted) probeSock = null; // ownership moved to the active session
    } catch (e) {
      // Keep Resume active while Primary is unavailable/restricted.
      return;
    } finally {
      if (probeSock) {
        try {
          if (probeSock?.ws?.close) probeSock.ws.close();
          else if (probeSock?.socket?.close) probeSock.socket.close();
          else if (probeSock?.end) probeSock.end();
        } catch (_) {}
      }
    }
  }
}

// Baileys socket creation
async function createOrGetSocket(sessionDir, sessionId, socketRole = null) {
  let baileys;
  try {
    baileys = await import('@whiskeysockets/baileys');
  } catch (e) {
    logger.error('Please npm install @whiskeysockets/baileys', e?.message || e);
    throw e;
  }

  const {
    makeWASocket,
    prepareWAMessageMedia,
    useMultiFileAuthState
  } = baileys;

  if (!fs.existsSync(sessionDir)) fs.mkdirSync(sessionDir, { recursive: true });

  let state, saveCreds;
  try {
    ({ state, saveCreds } = await useMultiFileAuthState(sessionDir));
  } catch (e) {
    appendSessionLog(sessionId, '[ERROR] Auth state load failed: ' + (e?.message || e));
    throw e;
  }

  // Use Baileys' own defaults for browser + WhatsApp Web version.
  // Passing a fetched/custom version or a fixed Mac/Safari tuple was the
  // unstable part of the previous build. The official docs show that the
  // browser/version options are optional and Baileys supplies defaults.
  // Prefer the live WhatsApp Web version when this Baileys build exposes it.
  // A stale bundled/default version can generate a code/QR but WhatsApp may reject linking.
  let liveWaVersion = null;
  try {
    if (typeof baileys.fetchLatestWaWebVersion === 'function') {
      const latestWa = await baileys.fetchLatestWaWebVersion();
      if (Array.isArray(latestWa?.version) && latestWa.version.length >= 3) {
        liveWaVersion = latestWa.version;
        appendSessionLog(sessionId, `[WHATSAPP] Using live WhatsApp Web version ${liveWaVersion.join('.')}`);
      }
    }
  } catch (e) {
    appendSessionLog(sessionId, `[WHATSAPP] Live version lookup failed; using Baileys default: ${e?.message || e}`);
  }

  const socketConfig = {
    ...(liveWaVersion ? { version: liveWaVersion } : {}),
    logger: pino({ level: 'silent' }),
    auth: state,
    markOnlineOnConnect: false,
    syncFullHistory: false,
    keepAliveIntervalMs: 20000,
    connectTimeoutMs: 60000,
    generateHighQualityLinkPreview: true,
    linkPreviewImageThumbnailWidth: 1200,
  };

  let sock = null;
  let lastError = null;

  for (let attempt = 1; attempt <= 8; attempt++) {
    try {
      // Re-read auth state before every construction attempt so a failed
      // socket cannot leave us retrying a stale in-memory key store.
      if (attempt > 1) {
        try {
          ({ state, saveCreds } = await useMultiFileAuthState(sessionDir));
          socketConfig.auth = state;
        } catch (e) {
          lastError = e;
          appendSessionLog(sessionId, `[WARN] Auth state reload failed (${attempt}/8): ${e?.message || e}`);
          await sleep(Math.min(5000 * attempt, 30000));
          continue;
        }
      }

      sock = makeWASocket(socketConfig);
      // Explicit connection state prevents the sender loop from treating
      // registered auth as an already-open WhatsApp WebSocket.
      sock.__dkConnectionOpen = false;
      sock.__dkSocketRole = socketRole || path.basename(sessionDir).toLowerCase();
      sock.__dkRetired = false;
      lastError = null;
      break;
    } catch (e) {
      lastError = e;
      const msg = String(e?.message || e);
      appendSessionLog(sessionId, `[WARN] Socket creation failed (${attempt}/8): ${msg}`);
      if (e?.stack) logger.debug({ sessionId, stack: e.stack }, 'Baileys socket creation stack');

      // This specifically handles the screenshot error without destroying
      // credentials. Keep retrying indefinitely from attemptReconnect().
      await sleep(Math.min(5000 * attempt, 30000));
    }
  }

  if (!sock) {
    throw lastError || new Error('Socket creation failed after retries');
  }

  if (sock?.ev?.on) {
    sock.ev.on('creds.update', async () => {
      try {
        if (typeof saveCreds === 'function') await saveCreds();
        try { pruneAuthFiles(sessionDir, sessionId); } catch (e) {}
      } catch (e) {
        appendSessionLog(sessionId, 'creds.update handler error: ' + (e?.message || e));
      }
    });
  }

  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect } = update;

    if (connection === 'close') {
      const current = SESSIONS[sessionId];

      // Retired/probe sockets are intentionally one-shot. Never reconnect them.
      if (sock.__dkRetired || sock.__dkSocketRole === 'primary-probe') return;

      // Ignore close events from any socket that is no longer the active socket.
      // During failover the old socket is deliberately detached before close().
      if (current && current.sock !== sock) return;

      // A credentials replacement or an active failover transition deliberately
      // closes/changes the socket. Never start a second reconnect from that close.
      if (current && (current.credentialReplacementInProgress || current.failoverLock)) {
        return;
      }

      sock.__dkConnectionOpen = false;
      if (current) current.sock = null;

      const errorMsg = lastDisconnect?.error?.message || lastDisconnect?.error || 'unknown';
      appendSessionLog(sessionId, 'Socket closed: ' + errorMsg);

      if (isLoggedOutUpdate(update)) {
        const s = SESSIONS[sessionId];
        if (s && !s.stopped) {
          if (s.activeCredentialSlot === 'primary' &&
              fs.existsSync(path.join(s.sessionDir, s.resumeAuthDir || 'resume', 'creds.json'))) {

            // Do NOT set awaitingCredentials=true before failover. That flag
            // intentionally pauses startSendingLoop and was causing the old
            // implementation to leave the session stopped.
            s.awaitingCredentials = false;
            s.lastAuthError = String(errorMsg);
            s.runningLoop = false;
            s.reconnectAttempts = 0;
            s.firstReconnectTime = null;
            persistSessionFiles(sessionId);

            appendSessionLog(sessionId, '[FAILOVER] Primary credentials logged out/expired. Switching to authorized resume credentials...');
            switchToResumeCredentials(sessionId).catch(err => {
              const currentSession = SESSIONS[sessionId];
              if (currentSession && !currentSession.stopped) {
                currentSession.awaitingCredentials = false;
                currentSession.lastAuthError = String(err?.message || err);
                persistSessionFiles(sessionId);
              }
              appendSessionLog(sessionId, '[FAILOVER] Backup switch failed: ' + (err?.message || err));
            });
          } else {
            s.awaitingCredentials = true;
            s.lastAuthError = String(errorMsg);
            s.sock = null;
            s.runningLoop = false;
            s.reconnectAttempts = 0;
            s.firstReconnectTime = null;
            persistSessionFiles(sessionId);
            appendSessionLog(sessionId, 'Credentials expired/logged out. No resume credentials available; session preserved.');
          }
        }
        return;
      }

      const s = SESSIONS[sessionId];
      if (s && !s.stopped && !s.awaitingCredentials) {
        appendSessionLog(sessionId, '[WARN] Connection closed; starting reconnect...');
        attemptReconnect(sessionId).catch(err =>
          appendSessionLog(sessionId, 'attemptReconnect error: ' + (err?.message || err))
        );
      }
    }

    if (connection === 'open') {
      sock.__dkConnectionOpen = true;
      appendSessionLog(sessionId, '[OK] Socket open and connected to WhatsApp');
      const s = SESSIONS[sessionId];
      if (s) {
        s.reconnectAttempts = 0;
        s.firstReconnectTime = null;
        s.consecutiveSendErrors = 0;
      }
      try { startSessionWatch(sessionId); } catch (e) {}
    }
  });

  return sock;
}
// Wait for the actual WhatsApp socket connection, not merely registered auth state.
// A registered authState/user can exist while the WebSocket is still connecting;
// sending media during that window can produce "Connection Closed".
async function waitForSocketOpen(sessionId, timeoutMs = 60000) {
  const s = SESSIONS[sessionId];
  if (!s || !s.sock) throw new Error('No session or socket');
  const sock = s.sock;

  // Fast path only when the socket is genuinely open.
  if (sock.__dkConnectionOpen === true || sock?.ws?.readyState === 1) return true;

  return new Promise((resolve, reject) => {
    let done = false;
    const to = setTimeout(() => {
      if (!done) {
        done = true;
        reject(new Error('timeout'));
      }
    }, timeoutMs);

    const handler = (update) => {
      const { connection } = update;
      if (connection === 'open') {
        sock.__dkConnectionOpen = true;
        if (!done) {
          done = true;
          clearTimeout(to);
          sock.ev.off('connection.update', handler);
          resolve(true);
        }
      } else if (connection === 'close') {
        if (!done) {
          done = true;
          clearTimeout(to);
          sock.ev.off('connection.update', handler);
          reject(new Error('Connection Closed'));
        }
      }
    };
    sock.ev.on('connection.update', handler);
  });
}


// Send through the currently active socket. Failover must never create a second
// sender loop; this helper only uses the one loop's current socket.

// Build a reliable manual YouTube link preview with a high-quality uploaded
// thumbnail. Ordinary text messages remain unchanged.
async function addYouTubeLinkPreview(payload, sock) {
  if (!payload || typeof payload.text !== 'string') return payload;
  const text = payload.text;
  const match = text.match(/https?:\/\/(?:www\.)?(?:youtube\.com\/(?:watch\?v=[^\s&]+|shorts\/[^\s?]+|live\/[^\s?]+|channel\/[^\s?]+|@[^\s?]+)|youtu\.be\/[^\s?&]+)/i);
  if (!match) return payload;

  const url = match[0].replace(/[),.!?]+$/g, '');
  try {
    const isVideo = /(?:youtube\.com\/(?:watch\?v=|shorts\/|live\/)|youtu\.be\/)/i.test(url);
    const oembedUrl = isVideo
      ? 'https://www.youtube.com/oembed?format=json&url=' + encodeURIComponent(url)
      : null;

    let meta = {};
    if (oembedUrl) {
      try {
        const metaRes = await fetch(oembedUrl, { headers: { 'user-agent': 'Mozilla/5.0' } });
        if (metaRes.ok) meta = await metaRes.json();
      } catch (_) {}
    }

    let videoId = null;
    const idMatch = url.match(/(?:youtube\.com\/(?:watch\?v=|shorts\/|live\/)|youtu\.be\/)([^?&#/]+)/i);
    if (idMatch) videoId = idMatch[1];

    // Always keep the thumbnail tied to THIS exact URL/video. The oEmbed
    // thumbnail is preferred because it is generated for the exact video;
    // ytimg is only a fallback for the same video ID.
    const thumbnailUrls = [];
    if (meta.thumbnail_url) thumbnailUrls.push(meta.thumbnail_url);
    if (videoId) {
      thumbnailUrls.push('https://i.ytimg.com/vi/' + videoId + '/hq720.jpg');
      thumbnailUrls.push('https://i.ytimg.com/vi/' + videoId + '/maxresdefault.jpg');
      thumbnailUrls.push('https://i.ytimg.com/vi/' + videoId + '/hqdefault.jpg');
    }

    // For channel/handle links, fetch the page's og:image so the channel
    // preview can also have its own image instead of a generic fallback.
    if (!videoId && !meta.thumbnail_url) {
      try {
        const pageRes = await fetch(url, { headers: { 'user-agent': 'Mozilla/5.0' } });
        if (pageRes.ok) {
          const html = await pageRes.text();
          const og = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
            || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
          const ogTitle = html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i)
            || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:title["']/i);
          if (og?.[1]) thumbnailUrls.unshift(og[1]);
          if (!meta.title && ogTitle?.[1]) meta.title = ogTitle[1];
        }
      } catch (_) {}
    }

    let thumbnailBuffer = null;
    let selectedThumbnailUrl = null;
    for (const thumbnailUrl of thumbnailUrls) {
      try {
        const imageRes = await fetch(thumbnailUrl, { headers: { 'user-agent': 'Mozilla/5.0' } });
        if (!imageRes.ok) continue;
        const buf = Buffer.from(await imageRes.arrayBuffer());
        if (buf.length > 5000) {
          thumbnailBuffer = buf;
          selectedThumbnailUrl = thumbnailUrl;
          break;
        }
      } catch (_) {}
    }

    const linkPreview = {
      'canonical-url': url,
      'matched-text': url,
      title: String(meta.title || 'YouTube'),
      description: String(meta.author_name || 'YouTube'),
      previewType: 0,
      originalThumbnailUrl: selectedThumbnailUrl || undefined,
      linkPreviewMetadata: {
        linkMediaDuration: 0,
        socialMediaPostType: 3
      }
    };

    // Give WhatsApp BOTH thumbnail forms. Most clients use jpegThumbnail for
    // the small preview; clients supporting the large card can use the uploaded
    // highQualityThumbnail. Both are built from the exact image fetched above.
    if (thumbnailBuffer && sock && typeof sock.waUploadToServer === 'function') {
      try {
        // This helper is outside createOrGetSocket, so prepareWAMessageMedia
        // must be imported here instead of relying on createOrGetSocket's local variable.
        const { prepareWAMessageMedia: preparePreviewMedia } = await import('@whiskeysockets/baileys');
        const { imageMessage } = await preparePreviewMedia(
          { image: thumbnailBuffer },
          {
            upload: sock.waUploadToServer,
            mediaTypeOverride: 'thumbnail-link',
            options: { timeout: 20000 }
          }
        );
        if (imageMessage) {
          if (imageMessage.jpegThumbnail && imageMessage.jpegThumbnail.length) {
            linkPreview.jpegThumbnail = Buffer.from(imageMessage.jpegThumbnail);
          }
          imageMessage.width = Number(imageMessage.width) || 1280;
          imageMessage.height = Number(imageMessage.height) || 720;
          linkPreview.highQualityThumbnail = imageMessage;
        }
      } catch (e) {
      }
    }

    return { ...payload, linkPreview };
  } catch (_) {
    return payload;
  }
}
async function sendOnActiveSocket(sessionId, jid, payload) {
  const s = SESSIONS[sessionId];
  if (!s || s.stopped || s.deleting) throw new Error('Session is not ready');
  await waitForSocketOpen(sessionId, 60000);
  if (!s.sock) throw new Error('Socket unavailable');

  const activeSock = s.sock;
  const sendingPrimaryGroup = s.target === 'gc' && s.activeCredentialSlot === 'primary';
  const finalPayload = await addYouTubeLinkPreview(payload, activeSock);

  // IMPORTANT: attach the messages.update listener BEFORE sendMessage().
  // WhatsApp/Baileys may emit the ERROR acknowledgement immediately after
  // sendMessage() is called. Attaching it afterwards can miss the rejection,
  // which makes a suspended Primary group look like a successful send.
  let ackPromise = null;
  let cleanupAck = () => {};

  if (sendingPrimaryGroup && activeSock?.ev?.on) {
    let messageId = '';
    let remoteJid = String(jid);
    let settled = false;
    let timer = null;

    ackPromise = new Promise((resolve, reject) => {
      const cleanup = () => {
        try { activeSock.ev.off?.('messages.update', onUpdate); } catch (_) {}
        if (timer) clearTimeout(timer);
      };
      cleanupAck = cleanup;

      const finishResolve = () => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve();
      };
      const finishReject = (reason) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(reason instanceof Error ? reason : new Error(String(reason)));
      };

      const onUpdate = (updates) => {
        for (const item of (Array.isArray(updates) ? updates : [updates])) {
          const key = item?.key || {};
          if (!messageId || String(key.id || '') !== messageId) continue;
          if (key.remoteJid && String(key.remoteJid) !== remoteJid) continue;

          const status = item?.update?.status;
          const statusText = String(status || '').toLowerCase();

          // Baileys WAMessageStatus.ERROR is 0. Also handle string forms.
          if (status === 0 || statusText === 'error') {
            finishReject(new Error('WhatsApp rejected the group message (message status ERROR)'));
            return;
          }

          // SERVER_ACK (2) or later delivery/read/play status means WhatsApp
          // accepted the outgoing message.
          const numericStatus = Number(status);
          if (Number.isFinite(numericStatus) && numericStatus >= 2) {
            finishResolve();
            return;
          }
          if (/server.?ack|delivery.?ack|read|played/i.test(statusText)) {
            finishResolve();
            return;
          }
        }
      };

      try {
        activeSock.ev.on('messages.update', onUpdate);
      } catch (_) {
        resolve();
        return;
      }

      // Do not hold the sending loop for a long time when WhatsApp gives no
      // explicit acknowledgement. Normal sends continue after this short
      // safety window; an explicit ERROR always fails immediately.
      timer = setTimeout(() => finishResolve(), 5000);

    });

    // sendMessage() fills these values after the Promise has been created.
    // IMPORTANT: do this OUTSIDE the Promise executor. The executor runs
    // synchronously, so assigning ackPromise.__setMessage inside it would
    // attempt to set a property on null before ackPromise receives the Promise.
    ackPromise.__setMessage = (id, remote) => {
      messageId = String(id || '');
      remoteJid = String(remote || jid);
    };
  }

  let sent;
  try {
    sent = await activeSock.sendMessage(jid, finalPayload);
  } catch (e) {
    cleanupAck();
    throw e;
  }

  if (ackPromise && sent?.key?.id) {
    try {
      ackPromise.__setMessage?.(sent.key.id, sent.key.remoteJid || jid);
      await ackPromise;
    } catch (e) {
      // Keep the exact WhatsApp rejection as a send error so the caller's
      // Primary -> Resume failover path handles it immediately.
      throw e;
    }
  } else if (ackPromise) {
    cleanupAck();
  }

  return sent;
}

// Always-on sender loop (message / image / sticker / video / document / audio / voice based on sessionType)
async function startSendingLoop(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s) throw new Error('Session not found');
  if (s.runningLoop) return;
  s.runningLoop = true;
  // Keep one global send schedule across Primary -> Resume failover.
  // This prevents the Resume socket from sending immediately or creating a second loop.
  if (!Number.isFinite(s.nextSendAt)) s.nextSendAt = 0;

  if (s.awaitingCredentials) {
    s.runningLoop = false;
    appendSessionLog(sessionId, 'Waiting for replacement creds.json; sending loop paused.');
    return;
  }

  appendSessionLog(sessionId, `[START] Started sending loop (type=${s.sessionType || 'message'})`);

  let index = 0;
  while (SESSIONS[sessionId]) {
    try {
      if (s.deleting || s.stopped) {
        appendSessionLog(sessionId, 'startSendingLoop: session is deleting/stopped, exiting loop');
        break;
      }

      // Audio/Voice media is uploaded after Start, one file at a time.
      // Never try to send until the frontend has finished the complete queue.
      if ((s.sessionType === 'audio' || s.sessionType === 'voice') && !s.mediaReady) {
        await sleep(500);
        continue;
      }

      // Voice Server is an UNLIMITED repeating queue. Saved voices must never
      // complete the session automatically. Once the last saved voice is sent,
      // the queue wraps back to voice #1 and continues forever until the user
      // manually stops/deletes the session or replaces the voice list.
      if (s.sessionType === 'voice') {
        s.voiceCompleted = false;
      }

      if (s.failoverLock) {
        // Primary -> Resume switch owns the socket transition. Do not let the
        // sender loop start a parallel reconnect while failover is in progress.
        await sleep(300);
        continue;
      }

      if (!s.sock) {
        if (!s.reconnectLock && !s.awaitingCredentials && !s.failoverLock) {
          attemptReconnect(sessionId).catch(err =>
            appendSessionLog(sessionId, 'Loop reconnect error: ' + (err?.message || err))
          );
        }
        await sleep(2000);
        continue;
      }

      try {
        // waitForSocketOpen resolves when the active socket is OPEN. It does not
        // return a boolean, so do not treat its undefined success value as false.
        await waitForSocketOpen(sessionId, 60000);
      } catch (e) {
        appendSessionLog(sessionId, '[SEND] Socket is not open yet: ' + (e?.message || e));
        await sleep(2000);
        continue;
      }

      // Never send early after a failover/edit/reconnect. The delay belongs to the
      // session, not to a particular WhatsApp socket, so Primary -> Resume keeps it.
      const remainingDelay = Math.max(0, Number(s.nextSendAt || 0) - Date.now());
      if (remainingDelay > 0) {
        await sleep(remainingDelay);
        if (!SESSIONS[sessionId] || s.stopped || s.deleting) break;
      }

      const sessionType = s.sessionType || 'message';
      const contacts = s.contacts || [];
      const messages = s.messages || [];
      const mediaFiles = s.mediaFiles || [];
      const prefixName = String(s.prefixName || '').trim();
      const lastPrefixName = String(s.lastPrefixName || '').trim();
      const target = s.target;
      const groupId = s.groupId;
      const mentionType = s.mentionType || 'none';
      const mentionNumbers = Array.isArray(s.mentionNumbers) ? s.mentionNumbers : [];

      const contact = (contacts.length) ? contacts[index % contacts.length] : null;

      let retryCurrentCycle = false;
      try {
        const baileys = await import('@whiskeysockets/baileys');
        let jid;

        if (target === 'gc') {
          jid = (groupId + '@g.us');
        } else {
          jid = contact ? baileys.jidNormalizedUser(contact + '@s.whatsapp.net') : null;
        }

        if (!jid) throw new Error('Invalid JID');

        // Build mention data for the current message.
        // IMPORTANT: `all_tag` uses WhatsApp/Baileys' native @all flag.
        // It must NOT load the group roster or add individual member JIDs.
        let activeMentionJids = [];
        let useNativeAllMention = false;

        if (target === 'gc' && mentionType !== 'none') {
          if (mentionType === 'all_tag') {
            useNativeAllMention = true;
          } else if (mentionType === 'all_group') {
            // Existing "All Tag — All Group Members (auto)" behavior is unchanged.
            try {
              const metadata = await s.sock.groupMetadata(jid);
              activeMentionJids = (metadata?.participants || [])
                .map(p => p?.id)
                .filter(Boolean);
            } catch (e) {
              appendSessionLog(sessionId, '[WARN] Could not load group members for mentions: ' + (e?.message || e));
            }
          } else if (mentionNumbers.length) {
            activeMentionJids = mentionNumbers.map(n => n + '@s.whatsapp.net');
            if (mentionType === 'single') {
              activeMentionJids = [activeMentionJids[index % activeMentionJids.length]];
            }
          }
        }

        const mentionLabels = activeMentionJids.map(x => String(x).split('@')[0]);
        const appendMentions = (text) => {
          const base = String(text || '').trim();

          // Native @All: only the native @all marker is added.
          // No group metadata lookup and no individual member mentions.
          if (useNativeAllMention) {
            return base ? `@all ${base}` : '@all';
          }

          if (!activeMentionJids.length) return base;
          const tags = mentionLabels.map(n => '@' + n).join(' ');
          return base ? `${tags} ${base}` : tags;
        };

        if (sessionType === 'sticker') {
          // Sticker mode: the selected Messages File entry and the selected
          // sticker are ONE logical cycle. The text is sent first and the
          // sticker is sent immediately after it, with NO separate timer,
          // index, counter, or second loop. The same index is used for both,
          // so message #N always goes with sticker #N and the next delay starts
          // only after BOTH have been sent.
          if (!mediaFiles.length) {
            appendSessionLog(sessionId, '[ERROR] No sticker files available, waiting...');
            await sleep(5000);
            continue;
          }
          const stickerPath = mediaFiles[index % mediaFiles.length];
          if (!fs.existsSync(stickerPath)) {
            appendSessionLog(sessionId, `[ERROR] Sticker file missing: ${path.basename(stickerPath)}`);
            index++;
            s.nextSendAt = Date.now() + safeDelayMs(s.delayMs, 5000);
            continue;
          }
          const stickerBuffer = fs.readFileSync(stickerPath);
          const stickerMessage = (messages.length) ? messages[index % messages.length] : '';
          const stickerText = appendMentions([prefixName, stickerMessage, lastPrefixName].filter(Boolean).join(' ').trim());
          // IMPORTANT: do not schedule these as two sends. Keep them in the
          // same loop iteration so there is exactly one logical cycle number
          // and one delay for the text + sticker pair. Text is intentionally
          // sent first so WhatsApp displays it immediately above the sticker.
          if (stickerText) {
            const stickerTextPayload = { text: stickerText };
            if (useNativeAllMention) stickerTextPayload.mentionAll = true;
            else if (activeMentionJids.length) stickerTextPayload.mentions = activeMentionJids;
            await sendOnActiveSocket(sessionId, jid, stickerTextPayload);
          }
          await sendOnActiveSocket(sessionId, jid, { sticker: stickerBuffer });
          s.lastUsed = Date.now();
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, `[OK] Sticker + Message cycle sent to ${jid} [${path.basename(stickerPath)}]`);

        } else if (sessionType === 'image') {
          // Image mode: optional prefix + required message[i] as caption, cycle through images one-by-one. Blank prefix is valid.
          if (!mediaFiles.length) {
            appendSessionLog(sessionId, '[ERROR] No image files available, waiting...');
            await sleep(5000);
            continue;
          }
          const imagePath = mediaFiles[index % mediaFiles.length];
          if (!fs.existsSync(imagePath)) {
            appendSessionLog(sessionId, `[ERROR] Image file missing: ${path.basename(imagePath)}`);
            index++;
            s.delayMs = safeDelayMs(s.delayMs, 5000);
      await sleep(s.delayMs);
            continue;
          }
          const imageBuffer = fs.readFileSync(imagePath);
          const messageToSend = (messages.length) ? messages[index % messages.length] : '';
          const fullCaption = appendMentions([prefixName, messageToSend, lastPrefixName].filter(Boolean).join(' ').trim());

          // Put the text INSIDE the image message as WhatsApp's native caption.
          // Do not send a separate text message, otherwise users receive two
          // bubbles (text first + image second).
          const imagePayload = { image: imageBuffer };
          if (fullCaption) imagePayload.caption = fullCaption;
          if (useNativeAllMention) imagePayload.mentionAll = true;
          else if (activeMentionJids.length) imagePayload.mentions = activeMentionJids;
          await sendOnActiveSocket(sessionId, jid, imagePayload);
          s.lastUsed = Date.now();
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, `[OK] Image sent to ${jid} [${path.basename(imagePath)}]`);

        } else if (sessionType === 'voice') {
          // Voice Server: send the same optional Prefix + Message File +
          // Mention/Tag system used by the other servers, then send the
          // saved recording as a native WhatsApp PTT voice note. Text is sent
          // separately because native AudioMessage does not reliably support
          // captions; sendOnActiveSocket also applies the existing YouTube
          // preview builder, so YouTube video/channel links keep their full
          // title/preview image behavior.
          if (!mediaFiles.length) {
            appendSessionLog(sessionId, '[ERROR] No voice recordings available, waiting...');
            await sleep(5000);
            continue;
          }
          // Always wrap around the saved voice list. There is NO completion
          // point: if 6 voices are uploaded, they become 1→2→3→4→5→6→1→2→...
          // forever, using the normal session delay between every voice.
          let voiceIndex = Number.isFinite(Number(s.voiceIndex)) ? Number(s.voiceIndex) : 0;
          if (voiceIndex < 0) voiceIndex = 0;
          voiceIndex = voiceIndex % mediaFiles.length;
          s.voiceIndex = voiceIndex;
          s.voiceCompleted = false;
          let voicePath = mediaFiles[voiceIndex];
          if (!fs.existsSync(voicePath)) {
            appendSessionLog(sessionId, `[ERROR] Voice recording missing: ${path.basename(voicePath)}`);
            s.voiceIndex = voiceIndex + 1;
            s.nextSendAt = Date.now() + safeDelayMs(s.delayMs, 5000);
            continue;
          }

          const voiceMessage = (messages.length) ? messages[voiceIndex % messages.length] : '';
          const voiceText = appendMentions([prefixName, voiceMessage, lastPrefixName].filter(Boolean).join(' ').trim());

          // Prepare/normalize the voice BEFORE either WhatsApp message is sent.
          // This keeps conversion time completely outside the text+voice pair,
          // so there is no conversion-induced gap between the two messages.
          // Accept normal audio OR video here. If the selected file is a
          // video, extract its first audio stream to OGG/Opus only when this
          // file actually reaches the send queue. Never convert all selected
          // videos during Start.
          if (!/\.(ogg|opus)$/i.test(voicePath)) {
            const normalizedVoicePath = voicePath + '.voice.ogg';
            try {
              await convertVoiceToOggOpus(voicePath, normalizedVoicePath);
              fs.unlinkSync(voicePath);
              fs.renameSync(normalizedVoicePath, voicePath.replace(/\.[^.]+$/, '') + '.voice.ogg');
              s.mediaFiles[voiceIndex] = voicePath = voicePath.replace(/\.[^.]+$/, '') + '.voice.ogg';
            } catch (normalizeErr) {
              try { if (fs.existsSync(normalizedVoicePath)) fs.unlinkSync(normalizedVoicePath); } catch (_) {}
              throw new Error('Voice/Video-to-Voice conversion failed: ' + (normalizeErr?.message || normalizeErr));
            }
          }
          const voiceBuffer = fs.readFileSync(voicePath);
          const voicePayload = {
            audio: voiceBuffer,
            mimetype: 'audio/ogg; codecs=opus',
            ptt: true
          };

          // Text + Voice are one logical cycle. Start both WhatsApp sends
          // together so they are not separated by the configured delay or an
          // intentional 1-second wait. WhatsApp still renders them as two
          // messages because a text and native PTT cannot be one bubble.
          if (voiceText) {
            const textPayload = { text: voiceText };
            if (useNativeAllMention) textPayload.mentionAll = true;
            else if (activeMentionJids.length) textPayload.mentions = activeMentionJids;
            await Promise.all([
              sendOnActiveSocket(sessionId, jid, textPayload),
              sendOnActiveSocket(sessionId, jid, voicePayload)
            ]);
          } else {
            await sendOnActiveSocket(sessionId, jid, voicePayload);
          }
          s.lastUsed = Date.now();
          s.consecutiveSendErrors = 0;
          const voiceNumber = voiceIndex + 1;
          appendSessionLog(sessionId, `[OK] Voice note ${voiceNumber}/${mediaFiles.length} sent to ${jid} [${path.basename(voicePath)}]${voiceText ? ' with Prefix/Message/Tag' : ''}`);
          // Advance and wrap the voice queue on the SAME global session
          // schedule. There is deliberately no DONE state: after the final
          // saved voice, the next cycle starts again at voice #1 forever.
          s.voiceIndex = (voiceIndex + 1) % mediaFiles.length;
          s.voiceCompleted = false;
          s.nextSendAt = Date.now() + safeDelayMs(s.delayMs, 5000);
          appendSessionLog(sessionId, `[QUEUE] Next voice ${s.voiceIndex + 1}/${mediaFiles.length} scheduled; Voice Server remains active (unlimited loop).`);


        } else if (sessionType === 'video' || sessionType === 'document' || sessionType === 'audio') {
          if (!mediaFiles.length) {
            appendSessionLog(sessionId, `[ERROR] No ${sessionType} files available, waiting...`);
            await sleep(5000);
            continue;
          }
          const mediaPath = mediaFiles[index % mediaFiles.length];
          if (!fs.existsSync(mediaPath)) {
            appendSessionLog(sessionId, `[ERROR] ${sessionType === 'video' ? 'Video' : sessionType === 'document' ? 'Document' : 'Audio'} file missing: ${path.basename(mediaPath)}`);
            index++;
            s.nextSendAt = Date.now() + safeDelayMs(s.delayMs, 5000);
            continue;
          }
          const mediaMessage = (messages.length) ? messages[index % messages.length] : '';
          const mediaText = appendMentions([prefixName, mediaMessage, lastPrefixName].filter(Boolean).join(' ').trim());
          // For video/document, WhatsApp/Baileys supports a native caption on
          // the media message. Keep the caption in the same bubble instead of
          // sending a separate text message. AudioMessage has no caption field
          // in the WhatsApp protocol, so audio keeps the existing text behavior.
          // Stream large media from disk instead of reading the whole file into
          // Node RAM for every loop cycle. This is especially important for video.
          let ext = path.extname(mediaPath).toLowerCase();
          const videoMime = ({'.mp4':'video/mp4','.m4v':'video/mp4','.mov':'video/quicktime','.webm':'video/webm','.mkv':'video/x-matroska'})[ext] || 'video/mp4';
          let audioMime = ({'.mp3':'audio/mpeg','.m4a':'audio/mp4','.aac':'audio/aac','.ogg':'audio/ogg','.opus':'audio/ogg','.wav':'audio/wav'})[ext] || 'audio/mpeg';
          let mediaPayload;
          if (sessionType === 'video') {
            mediaPayload = { video: { url: mediaPath }, mimetype: videoMime };
            // A YouTube link needs the normal text-preview path so WhatsApp can
            // receive the full title/thumbnail. For ordinary text, keep the
            // existing native video caption behavior.
            if (mediaText && hasYouTubeLink(mediaText)) {
              const previewTextPayload = await addYouTubeLinkPreview({ text: mediaText }, s.sock);
              if (useNativeAllMention) previewTextPayload.mentionAll = true;
              else if (activeMentionJids.length) previewTextPayload.mentions = activeMentionJids;
              // Send the YouTube preview text FIRST, then the video immediately
              // after it. Promise.all can race the two WhatsApp sends and cause
              // the preview metadata/thumbnail message to be lost on some
              // Baileys/WhatsApp combinations. There is no configured-delay gap
              // between these two sends.
              await sendOnActiveSocket(sessionId, jid, previewTextPayload);
              await sendOnActiveSocket(sessionId, jid, mediaPayload);
              mediaPayload = null;
            } else if (mediaText) {
              mediaPayload.caption = mediaText;
            }
            if (useNativeAllMention && mediaPayload) mediaPayload.mentionAll = true;
            else if (activeMentionJids.length && mediaPayload) mediaPayload.mentions = activeMentionJids;
          } else if (sessionType === 'document') {
            const docMime = mimeTypeForFile(mediaPath) || 'application/octet-stream';
            mediaPayload = { document: { url: mediaPath }, mimetype: docMime, fileName: path.basename(mediaPath) };
            if (mediaText) mediaPayload.caption = mediaText;
            if (useNativeAllMention) mediaPayload.mentionAll = true;
            else if (activeMentionJids.length) mediaPayload.mentions = activeMentionJids;
          } else {
            // Audio Server also accepts video files. Extract the first audio
            // stream lazily, one file at a time, so selecting many videos never
            // blocks Start. The converted OGG/Opus path is cached for later
            // cycles, so each source video is converted only once.
            if (!/\.(mp3|m4a|aac|ogg|opus|wav)$/i.test(mediaPath)) {
              const sourcePath = mediaPath;
              const convertedPath = sourcePath.replace(/\.[^.]+$/, '') + '.audio.ogg';
              try {
                await convertVoiceToOggOpus(sourcePath, convertedPath);
                try { fs.unlinkSync(sourcePath); } catch (_) {}
                s.mediaFiles[index % mediaFiles.length] = convertedPath;
                mediaPath = convertedPath;
                ext = '.ogg';
                audioMime = 'audio/ogg; codecs=opus';
              } catch (audioErr) {
                try { if (fs.existsSync(convertedPath)) fs.unlinkSync(convertedPath); } catch (_) {}
                throw new Error('Video-to-Audio conversion failed: ' + (audioErr?.message || audioErr));
              }
            }
            // AudioMessage does not reliably carry captions/mentions across
            // WhatsApp clients. Use the same proven text + media flow as Voice:
            // Prefix/Message/Tag are sent as a normal text message first (which
            // also gets the existing YouTube title/thumbnail preview), then the
            // native audio file is sent separately.
            mediaPayload = { audio: { url: mediaPath }, mimetype: audioMime, ptt: false };
            if (mediaText) {
              const audioTextPayload = await addYouTubeLinkPreview({ text: mediaText }, s.sock);
              if (useNativeAllMention) audioTextPayload.mentionAll = true;
              else if (activeMentionJids.length) audioTextPayload.mentions = activeMentionJids;
              // Audio captions are not reliable in WhatsApp. Start the text
              // and audio sends together so there is no intentional 1-second
              // (or configured-delay) gap between them. They remain two native
              // WhatsApp messages because text cannot be embedded reliably in an
              // AudioMessage bubble.
              await Promise.all([
                sendOnActiveSocket(sessionId, jid, audioTextPayload),
                sendOnActiveSocket(sessionId, jid, mediaPayload)
              ]);
              mediaPayload = null;
            }
          }
          if (mediaPayload) await sendOnActiveSocket(sessionId, jid, mediaPayload);
          s.lastUsed = Date.now();
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, `[OK] ${sessionType === 'video' ? 'Video' : sessionType === 'document' ? 'Document' : 'Audio'} sent to ${jid} [${path.basename(mediaPath)}]`);

        } else {
          // Default: text message mode (same as before)
          const messageToSend = (messages.length) ? messages[index % messages.length] : '';
          const fullMessage = appendMentions([prefixName, messageToSend, lastPrefixName].filter(Boolean).join(' ').trim());
          const textPayload = { text: fullMessage };
          if (useNativeAllMention) textPayload.mentionAll = true;
          else if (activeMentionJids.length) textPayload.mentions = activeMentionJids;
          await sendOnActiveSocket(sessionId, jid, textPayload);
          s.lastUsed = Date.now();
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, `[OK] Message sent to ${jid}`);
        }

        // One successful logical cycle = one message/image/sticker. Start the
        // configured delay only after that cycle has actually been sent.
        s.nextSendAt = Date.now() + safeDelayMs(s.delayMs, 5000);

      } catch (err) {
        // A failed logical cycle is also throttled, so a reconnect/failover
        // cannot cause an immediate duplicate send.
        s.nextSendAt = Date.now() + safeDelayMs(s.delayMs, 5000);
        const sendErrorText = String(err?.message || err);
        const primaryGroupFailoverError =
          s.target === 'gc' &&
          s.activeCredentialSlot === 'primary' &&
          isGroupRestrictedOrSuspendedError(err);
        if (!primaryGroupFailoverError) {
          appendSessionLog(sessionId, '[ERROR] Send failed: ' + sendErrorText);
        }

        // Group-level suspension/restriction can leave the Primary socket OPEN
        // while WhatsApp rejects sends to that group. Do not wait for ten
        // failed sends: immediately activate the authorized Resume account.
        if (
          primaryGroupFailoverError
        ) {
          appendSessionLog(
            sessionId,
            '[FAILOVER] Primary group send was rejected as suspended/restricted. Switching immediately to Resume.'
          );
          try {
            const switched = await switchToResumeCredentials(
              sessionId,
              'Primary group send rejected: suspended/restricted'
            );
            if (switched) {
              // The restriction response means this logical send was rejected.
              // Retry the same cycle on Resume instead of dropping the message.
              retryCurrentCycle = true;
              s.consecutiveSendErrors = 0;
              appendSessionLog(
                sessionId,
                '[FAILOVER] Resume is active; retrying the failed group cycle on Resume.'
              );
            } else {
              appendSessionLog(
                sessionId,
                '[FAILOVER] Resume switch was not completed; waiting before retrying.'
              );
            }
          } catch (failoverErr) {
            appendSessionLog(
              sessionId,
              '[FAILOVER] Immediate Resume switch failed: ' + String(failoverErr?.message || failoverErr)
            );
          }
        } else {
          s.consecutiveSendErrors = (s.consecutiveSendErrors || 0) + 1;
        }

        const MAX_CONSEC_SEND_FAIL = 10;

        if (!retryCurrentCycle && s.consecutiveSendErrors >= MAX_CONSEC_SEND_FAIL) {
          appendSessionLog(
            sessionId,
            `Reached ${MAX_CONSEC_SEND_FAIL} consecutive send failures. Reconnecting socket.`
          );
          s.consecutiveSendErrors = 0;
          s.sock = null;

          if (!s.reconnectLock && !s.stopped && !s.awaitingCredentials) {
            attemptReconnect(sessionId).catch(e =>
              appendSessionLog(sessionId, 'Failed to reconnect after send errors: ' + (e?.message || e))
            );
          }
        }
      }

      if (!retryCurrentCycle) index++;
      persistSessionFiles(sessionId);
      // Delay is enforced by nextSendAt at the top of the next cycle.

    } catch (e) {
      appendSessionLog(sessionId, 'Error in sending loop: ' + (e?.message || e));
      await sleep(2000);
    }
  }

  if (SESSIONS[sessionId]) SESSIONS[sessionId].runningLoop = false;
}


// ========== WhatsApp Pairing Code + Group Browser ==========
// Pair once, persist Baileys auth state, and reuse the same linked account
// after restarts. Pairing-only sessions do not start the message sender loop.
async function getParticipatingGroups(sock) {
  if (!sock || typeof sock.groupFetchAllParticipating !== 'function') {
    throw new Error('This Baileys version does not support groupFetchAllParticipating');
  }
  const all = await sock.groupFetchAllParticipating();
  return Object.values(all || {})
    .map(g => ({
      id: String(g?.id || ''),
      subject: String(g?.subject || 'Unnamed group'),
      owner: String(g?.owner || ''),
      size: Array.isArray(g?.participants) ? g.participants.length : 0,
      announce: !!g?.announce,
      restrict: !!g?.restrict
    }))
    .filter(g => g.id.endsWith('@g.us'))
    .sort((a, b) => a.subject.localeCompare(b.subject, undefined, { sensitivity: 'base' }));
}

function normalizePairingPhone(value) {
  return String(value || '').replace(/\D/g, '').replace(/^0+/, '');
}

app.post('/api/whatsapp/pairing/start', async (req, res) => {
  try {
    const auth = requireApprovedAuth(req);
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });

    const phone = normalizePairingPhone(req.body?.phone);
    if (!/^\d{7,15}$/.test(phone)) {
      return res.status(400).json({ ok: false, error: 'Enter WhatsApp number with country code, digits only' });
    }

    // Reuse an already-paired account instead of asking for a new code.
    const existing = Object.values(SESSIONS).find(s =>
      !s.stopped && s.pairingOnly &&
      (s.phone === phone || s.primaryPhone === phone)
    );
    if (existing?.sock && existing.sock.user) {
      return res.json({ ok: true, alreadyPaired: true, sessionId: existing.sessionId, phone: existing.phone || phone });
    }
    if (existing && existing.pairingCode) {
      return res.json({ ok: true, alreadyPaired: false, sessionId: existing.sessionId, pairingCode: existing.pairingCode, status: existing.pairingStatus || 'waiting' });
    }

    const sessionId = makeSessionId();
    const sessionDir = makeSessionDir(sessionId);
    const sockDir = sessionDir; // pairing auth lives in the session root for restore compatibility
    const baileys = await import('@whiskeysockets/baileys');
    const { makeWASocket, useMultiFileAuthState, Browsers } = baileys;
    const { state, saveCreds } = await useMultiFileAuthState(sockDir);
    let liveWaVersion = null;
    try {
      if (typeof baileys.fetchLatestWaWebVersion === 'function') {
        const latestWa = await baileys.fetchLatestWaWebVersion();
        if (Array.isArray(latestWa?.version) && latestWa.version.length >= 3) {
          liveWaVersion = latestWa.version;
          appendSessionLog(sessionId, `[PAIRING] Using live WhatsApp Web version ${liveWaVersion.join('.')}`);
        }
      }
    } catch (e) {
      appendSessionLog(sessionId, `[PAIRING] Live version lookup failed; using Baileys default: ${e?.message || e}`);
    }

    const s = {
      sessionId,
      sessionDir,
      username: auth.username,
      phone,
      primaryPhone: phone,
      primaryAuthDir: '.',
      resumeAuthDir: 'resume',
      activeCredentialSlot: 'primary',
      contacts: [], messages: [], mediaFiles: [], prefixName: '', lastPrefixName: '',
      delayMs: 5000, target: 'contacts', groupId: null, sessionType: 'message',
      mentionType: 'none', mentionNumbers: [],
      runningLoop: false, sock: null, stopped: false, deleting: false,
      awaitingCredentials: false, pairingOnly: true, pairingStatus: 'starting',
      pairingCode: null, groups: [], logs: [], createdAt: new Date().toISOString(),
      startedAt: Date.now(), reconnectAttempts: 0, reconnectLock: false,
      restartLock: false, failoverLock: false, credentialReplacementInProgress: false,
      firstReconnectTime: null, lastAuthError: null
    };
    SESSIONS[sessionId] = s;

    // Pairing-code login is sensitive to socket readiness. Use an explicit
    // browser identity and request the code only after WhatsApp emits its
    // initial QR/connecting event (not on a fixed sleep).
    const browser = (Browsers?.ubuntu ? Browsers.ubuntu('Chrome') : ['Ubuntu', 'Chrome', '120.0.0']);
    let sock = makeWASocket({
      ...(liveWaVersion ? { version: liveWaVersion } : {}),
      logger: pino({ level: 'silent' }),
      auth: state,
      browser,
      markOnlineOnConnect: true,
      syncFullHistory: false,
      keepAliveIntervalMs: 20000,
      connectTimeoutMs: 60000,
      printQRInTerminal: false
    });
    s.sock = sock;

    // Pair-code login can legitimately close the first socket with status 515
    // after WhatsApp sends pair-success. That 515 means "restart using the new
    // credentials", not "pairing failed". Keep the latest credential write as
    // a promise so the replacement socket never starts before creds.json is
    // fully updated.
    let lastCredsSave = Promise.resolve();

    let pairingReadyResolve;
    let pairingReadyReject;
    let pairingCodeRequested = false;
    const pairingReady = new Promise((resolve, reject) => {
      pairingReadyResolve = resolve;
      pairingReadyReject = reject;
    });
    const pairingReadyTimeout = setTimeout(() => {
      try { pairingReadyReject(new Error('WhatsApp socket did not become ready for pairing within 20 seconds')); } catch (_) {}
    }, 20000);

    const attachPairedSocketHandlers = (currentSock, currentState, currentSaveCreds, isInitial = false) => {
      currentSock.ev.on('creds.update', () => {
        lastCredsSave = lastCredsSave.then(async () => {
          try { await currentSaveCreds(); }
          catch (e) { appendSessionLog(sessionId, '[PAIRING] creds.save failed: ' + (e?.message || e)); throw e; }
        });
        return lastCredsSave.catch(() => {});
      });

      currentSock.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect, qr, isNewLogin } = update || {};

        // Official pairing flow: requestPairingCode only after the initial QR
        // event. This prevents generating a code before the registration socket
        // is ready.
        if (isInitial && !currentState.creds.registered && !pairingCodeRequested && qr) {
          pairingCodeRequested = true;
          clearTimeout(pairingReadyTimeout);
          try { pairingReadyResolve(); } catch (_) {}
        }

        // WhatsApp may emit isNewLogin and then close with 515. Mark the session
        // as restarting immediately; 515 is the expected post-pair restart.
        if (isNewLogin) {
          s.pairingStatus = 'restarting';
          s.awaitingCredentials = false;
          s.lastAuthError = null;
          persistSessionFiles(sessionId);
          appendSessionLog(sessionId, '[PAIRING] Pair-success received; saving new credentials and restarting socket...');
        }

        if (connection === 'open') {
          s.sock = currentSock;
          s.pairingStatus = 'paired';
          s.awaitingCredentials = false;
          s.lastAuthError = null;
          s.phone = extractWhatsAppPhoneFromSession(s) || phone;
          try {
            const freshGroups = await getParticipatingGroups(currentSock);
            // Only replace the saved list after a successful WhatsApp fetch.
            // A temporary fetch error must never erase already-known groups.
            if (Array.isArray(freshGroups)) s.groups = freshGroups;
          } catch (e) {
            appendSessionLog(sessionId, `[GROUPS] Refresh failed; keeping ${Array.isArray(s.groups) ? s.groups.length : 0} saved groups`);
          }
          try {
            const cp = path.join(sessionDir, 'creds.json');
            if (fs.existsSync(cp)) { s.credsHash = sha256File(cp); CREDS_HASH_TO_SESSION[s.credsHash] = sessionId; }
          } catch (_) {}
          persistSessionFiles(sessionId);
          appendSessionLog(sessionId, `[PAIRING] WhatsApp connected successfully: ${s.phone}`);
          appendSessionLog(sessionId, `[GROUPS] Loaded ${s.groups.length} groups`);
          return;
        }

        if (connection === 'close' && !s.stopped) {
          const code = Number(lastDisconnect?.error?.output?.statusCode || lastDisconnect?.error?.data?.statusCode || 0);
          const msg = lastDisconnect?.error?.message || String(lastDisconnect?.error || 'connection closed');

          if (code === 515 && !isInitial) {
            appendSessionLog(sessionId, '[PAIRING] Received 515 restart-required; reconnecting with freshly saved credentials...');
            return;
          }

          if (code === 515 && isInitial && pairingCodeRequested) {
            // Pairing succeeded on the WhatsApp side; wait for the credential
            // update, reload auth state from disk, and build a fresh socket.
            s.pairingStatus = 'restarting';
            try { await lastCredsSave; } catch (_) {}
            try {
              const fresh = await useMultiFileAuthState(sockDir);
              if (!fresh.state.creds.registered) throw new Error('Fresh pairing credentials were not saved');
              const newSock = makeWASocket({
                ...(liveWaVersion ? { version: liveWaVersion } : {}),
                logger: pino({ level: 'silent' }),
                auth: fresh.state,
                browser,
                markOnlineOnConnect: true,
                syncFullHistory: false,
                keepAliveIntervalMs: 20000,
                connectTimeoutMs: 60000,
                printQRInTerminal: false
              });
              sock = newSock;
              s.sock = newSock;
              attachPairedSocketHandlers(newSock, fresh.state, fresh.saveCreds, false);
              appendSessionLog(sessionId, '[PAIRING] Replacement socket created after 515. Waiting for connection...');
            } catch (e) {
              s.pairingStatus = 'failed';
              s.lastAuthError = e?.message || String(e);
              persistSessionFiles(sessionId);
              appendSessionLog(sessionId, '[PAIRING] 515 reconnect failed: ' + (e?.message || e));
            }
            return;
          }

          if (!pairingCodeRequested) {
            pairingCodeRequested = true;
            clearTimeout(pairingReadyTimeout);
            try { pairingReadyReject(new Error(msg || 'Connection Closed before pairing code was ready')); } catch (_) {}
          }

          if (isLoggedOutUpdate(update)) {
            s.pairingStatus = 'logged_out';
            s.awaitingCredentials = true;
            s.lastAuthError = msg;
          } else if (s.pairingStatus !== 'restarting') {
            s.pairingStatus = s.pairingStatus === 'paired' ? 'reconnecting' : 'failed';
          }
          persistSessionFiles(sessionId);
        }
      });
    };

    attachPairedSocketHandlers(sock, state, saveCreds, true);

    // Wait for socket readiness before requesting the pairing code.
    if (!state.creds.registered) {
      try {
        await pairingReady;
      } catch (e) {
        try { sock.ws?.close?.(); } catch (_) {}
        delete SESSIONS[sessionId];
        return res.status(504).json({ ok: false, error: e?.message || 'WhatsApp socket not ready for pairing' });
      }
      let pairingCode;
      try {
        pairingCode = await sock.requestPairingCode(phone);
      } catch (e) {
        s.pairingStatus = 'failed';
        s.lastAuthError = e?.message || String(e);
        persistSessionFiles(sessionId);
        try { sock.ws?.close?.(); } catch (_) {}
        return res.status(502).json({ ok: false, error: 'Pairing code request failed: ' + (e?.message || e) });
      }
      s.pairingCode = String(pairingCode || '').toUpperCase();
    } else {
      s.pairingStatus = 'paired';
      s.pairingCode = null;
    }
    s.pairingStatus = 'waiting';
    persistSessionFiles(sessionId);

    return res.json({ ok: true, sessionId, pairingCode: s.pairingCode, status: s.pairingStatus, phone });
  } catch (e) {
    logger.error('pairing start error', e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post('/api/whatsapp/pairing/status', async (req, res) => {
  try {
    const auth = requireApprovedAuth(req);
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });
    const sessionId = String(req.body?.sessionId || '');
    const s = SESSIONS[sessionId];
    if (!s || !s.pairingOnly) return res.status(404).json({ ok: false, error: 'Pairing session not found' });
    if (auth.role !== 'admin' && s.username !== auth.username) return res.status(403).json({ ok: false, error: 'Not authorized' });

    // Status polling must stay cheap: groups are loaded on connect and only
    // refreshed explicitly through /api/whatsapp/groups. Do NOT call
    // groupFetchAllParticipating() on every status poll.
    return res.json({ ok: true, sessionId, status: s.pairingStatus || 'unknown', phone: s.phone || '', pairingCode: s.pairingCode || '', groups: s.groups || [], groupCount: (s.groups || []).length });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post('/api/whatsapp/groups', async (req, res) => {
  try {
    const auth = requireApprovedAuth(req);
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });
    const sessionId = String(req.body?.sessionId || '');
    const s = SESSIONS[sessionId];
    if (!s || !s.pairingOnly) return res.status(404).json({ ok: false, error: 'Paired WhatsApp session not found' });
    if (auth.role !== 'admin' && s.username !== auth.username) return res.status(403).json({ ok: false, error: 'Not authorized' });
    if (!s.sock || !s.sock.user) return res.status(409).json({ ok: false, error: 'WhatsApp is not connected yet' });
    s.groups = await getParticipatingGroups(s.sock);
    return res.json({ ok: true, groups: s.groups, groupCount: s.groups.length });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ========== API ROUTES ==========

// Serve index.html
app.get('/', (req, res) => {
  getOrCreateApprovalKey(req, res);
  // Send the HTML directly and strip any accidental literal \\n sequences
  // that a hosting/proxy layer could prepend to the page.
  try {
    const html = fs.readFileSync(path.join(process.cwd(), 'index.html'), 'utf8')
      .replace(/(?:\\n)+/g, '');
    res.type('html').send(html);
  } catch (e) {
    res.sendFile(path.join(process.cwd(), 'index.html'));
  }
});

// Approval gate: username login is unavailable until this browser/device key is approved.
app.get('/api/approval/status', (req, res) => {
  const key = getOrCreateApprovalKey(req, res);
  const approved = isKeyApproved(key);
  const requests = loadApprovalRequests();
  res.json({ ok: true, key, approved, requested: !!requests[key] });
});

app.post('/api/approval/request', (req, res) => {
  try {
    const key = getOrCreateApprovalKey(req, res);
    const requests = loadApprovalRequests();
    requests[key] = { key, requestedAt: new Date().toISOString(), userAgent: String(req.headers['user-agent'] || '').slice(0, 300) };
    saveApprovalRequests(requests);
    const message = encodeURIComponent(`𝗛𝗲𝗹𝗹𝗼 𝗦𝗮𝗶𝗺 𝗞𝗵𝗮𝗻 𝗦𝗶𝗿,𝗣𝗹𝗲𝗮𝘀𝗲 𝗔𝗽𝗽𝗿𝗼𝘃𝗮𝗹 𝗠𝘆  𝗪𝗵𝗮𝘁𝘀𝗔𝗽𝗽 𝗞𝗲𝘆?:✅

${key}

𝗧𝗵𝗮𝗻𝗸 𝗬𝗼𝘂 💖`);
    const whatsappUrl = `https://wa.me/919052845410?text=${message}`;
    res.json({ ok: true, key, approved: isKeyApproved(key), whatsappUrl });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Approval request failed' });
  }
});


// Persistent server uptime (kept for compatibility with existing clients).
function getServerUptime() {
  const uptimeMs = Math.max(0, Date.now() - SERVER_START_TIME);
  const uptimeSeconds = Math.floor(uptimeMs / 1000);
  const days = Math.floor(uptimeSeconds / 86400);
  const hours = Math.floor((uptimeSeconds % 86400) / 3600);
  const minutes = Math.floor((uptimeSeconds % 3600) / 60);
  const seconds = uptimeSeconds % 60;
  return { uptimeMs, uptimeSeconds, uptimeFormatted: `${days} day ${hours} hour ${minutes} minute ${seconds} seconds`, startTime: new Date(SERVER_START_TIME).toISOString() };
}

app.get('/api/uptime', (req, res) => res.json({ ok: true, ...getServerUptime() }));

function readNetworkBytes() {
  try {
    const raw = fs.readFileSync('/proc/net/dev', 'utf8');
    let rx = 0, tx = 0;
    for (const line of raw.split('\n')) {
      const m = line.match(/^\s*([^:]+):\s*(.*)$/);
      if (!m) continue;
      const iface = m[1].trim();
      if (iface === 'lo') continue;
      const parts = m[2].trim().split(/\s+/).map(Number);
      if (parts.length >= 9) { rx += parts[0] || 0; tx += parts[8] || 0; }
    }
    return { rx, tx };
  } catch (e) { return { rx: 0, tx: 0 }; }
}

function getNetworkRate() {
  const now = Date.now();
  const cur = readNetworkBytes();
  if (!lastNetworkSample) { lastNetworkSample = cur; lastNetworkSampleAt = now; return { rxBps: 0, txBps: 0 }; }
  const dt = Math.max(0.25, (now - lastNetworkSampleAt) / 1000);
  const rxBps = Math.max(0, cur.rx - lastNetworkSample.rx) / dt;
  const txBps = Math.max(0, cur.tx - lastNetworkSample.tx) / dt;
  lastNetworkSample = cur; lastNetworkSampleAt = now;
  return { rxBps, txBps };
}

function getStorageStats() {
  try {
    if (typeof fs.statfsSync === 'function') {
      const st = fs.statfsSync(process.cwd());
      const total = Number(st.blocks) * Number(st.bsize);
      const free = Number(st.bfree) * Number(st.bsize);
      return { total, used: Math.max(0, total - free) };
    }
  } catch (e) {}
  return { total: 0, used: 0 };
}

app.get('/api/system-stats', (req, res) => {
  try {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const cpuCount = Math.max(1, os.cpus().length);
    const load = os.loadavg()[0] || 0;
    const cpuPercent = Math.min(100, Math.max(0, (load / cpuCount) * 100));
    const storage = getStorageStats();
    const net = getNetworkRate();
    const now = new Date();
    res.json({
      ok: true,
      // Dashboard clock is always India Standard Time (Asia/Kolkata).
      date: new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', day: '2-digit', month: '2-digit', year: 'numeric' }).format(now),
      time: new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(now),
      uptime: getServerUptime(),
      ram: { total: totalMem, used: Math.max(0, totalMem - freeMem), percent: totalMem ? ((totalMem-freeMem)/totalMem)*100 : 0 },
      storage: { total: storage.total, used: storage.used, percent: storage.total ? (storage.used/storage.total)*100 : 0 },
      cpu: { percent: cpuPercent, cores: cpuCount },
      network: net
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || 'System stats unavailable' });
  }
});

// User/admin approval is handled inside this same server panel.
// New accounts are created as pending; only the admin can approve or reject them.

function findUserByUsername(username) {
  const users = loadUsers();
  const requested = String(username || '').trim().toLowerCase();
  if (!requested) return null;
  return Object.values(users).find(u => String(u?.username || '').toLowerCase() === requested) || null;
}

function isApprovedUser(username) {
  const user = findUserByUsername(username);
  return !!user && (user.role === 'admin' || user.status === 'approved');
}

function createAuthToken(username, role) {
  const token = crypto.randomBytes(32).toString('hex');
  AUTH_TOKENS.set(token, { username, role, createdAt: Date.now() });
  return token;
}

function getAuthUser(req) {
  const cookies = parseCookies(req);
  const cookieToken = cookies.wa_auth;
  if (cookieToken && AUTH_TOKENS.has(cookieToken)) return AUTH_TOKENS.get(cookieToken);
  // Backward compatibility for old clients; new browser sessions use HttpOnly cookies.
  const header = String(req.headers.authorization || '');
  if (header.startsWith('Bearer ')) return AUTH_TOKENS.get(header.slice(7)) || null;
  return null;
}

function requireAdmin(req) {
  const auth = getAuthUser(req);
  if (!auth || auth.role !== 'admin') return null;
  const user = findUserByUsername(auth.username);
  if (!user || user.role !== 'admin' || user.status === 'disabled' || user.status === 'rejected') return null;
  return auth;
}

function requirePrimaryAdmin(req) {
  const auth = requireAdmin(req);
  if (!auth) return null;
  const user = findUserByUsername(auth.username);
  if (!user || !user.primaryAdmin) return null;
  return auth;
}

function saveApprovedKeys(keys) {
  const unique = [...new Set(keys.map(k => String(k || '').trim().toUpperCase()).filter(Boolean))];
  fs.writeFileSync(approvalFilePath, unique.join('\n') + (unique.length ? '\n' : ''), 'utf8');
  return unique;
}

function invalidateUserTokens(username) {
  for (const [token, auth] of AUTH_TOKENS.entries()) {
    if (auth.username === username) AUTH_TOKENS.delete(token);
  }
}

function requireApprovedAuth(req) {
  if (!isApprovalCookieApproved(req)) return null;
  const auth = getAuthUser(req);
  if (!auth || !isApprovedUser(auth.username)) return null;
  return auth;
}

// Admin creates the username. Users cannot self-register.
app.post('/api/admin/create-user', (req, res) => {
  try {
    if (!requireAdmin(req)) return res.status(403).json({ ok: false, error: 'Admin access required' });
    const username = String(req.body?.username || '').trim();
    if (!username || username.length < 3 || username.length > 32) {
      return res.status(400).json({ ok: false, error: 'Username must be 3-32 characters' });
    }
    if (!/^[A-Za-z0-9_.-]+$/.test(username)) {
      return res.status(400).json({ ok: false, error: 'Username may contain letters, numbers, dot, dash and underscore only' });
    }
    const users = loadUsers();
    if (Object.values(users).some(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(409).json({ ok: false, error: 'Username already exists' });
    }
    const userId = 'user_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7);
    const salt = crypto.randomBytes(16).toString('hex');
    const internalSecret = crypto.randomBytes(32).toString('hex');
    users[userId] = {
      username,
      password: '',
      passwordSalt: salt,
      passwordHash: hashPassword(internalSecret, salt),
      role: 'user',
      status: 'approved',
      createdAt: new Date().toISOString()
    };
    saveUsers(users);
    res.json({ ok: true, status: 'approved' });
  } catch (e) {
    logger.error('Admin create user error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to create user' });
  }
});

// Owner-only approval key management. Normal admins/users cannot access these routes.
app.post('/api/admin/approval-keys', (req, res) => {
  try {
    if (!requirePrimaryAdmin(req)) return res.status(403).json({ ok:false, error:'Primary Owner access required' });
    res.json({ ok:true, keys: loadApprovedKeys() });
  } catch (e) {
    logger.error('Approval key list error', e?.message || e);
    res.status(500).json({ ok:false, error:'Failed to load approval keys' });
  }
});

app.post('/api/admin/approval-key', (req, res) => {
  try {
    if (!requirePrimaryAdmin(req)) return res.status(403).json({ ok:false, error:'Primary Owner access required' });
    const key = String(req.body?.key || '').trim().toUpperCase();
    if (!key || key.length > 128) return res.status(400).json({ ok:false, error:'Valid approval key required' });
    const keys = saveApprovedKeys([...loadApprovedKeys(), key]);
    res.json({ ok:true, key, approved:true, count:keys.length });
  } catch (e) {
    logger.error('Approval key save error', e?.message || e);
    res.status(500).json({ ok:false, error:'Failed to save approval key' });
  }
});

app.post('/api/admin/approval-key/disable', (req, res) => {
  try {
    if (!requirePrimaryAdmin(req)) return res.status(403).json({ ok:false, error:'Primary Owner access required' });
    const key = String(req.body?.key || '').trim().toUpperCase();
    if (!key) return res.status(400).json({ ok:false, error:'Approval key required' });
    const keys = loadApprovedKeys().filter(k => String(k).toUpperCase() !== key);
    saveApprovedKeys(keys);
    res.json({ ok:true, key, disabled:true, count:keys.length });
  } catch (e) {
    logger.error('Approval key disable error', e?.message || e);
    res.status(500).json({ ok:false, error:'Failed to disable approval key' });
  }
});

// List users for the admin panel
app.post('/api/admin/users', (req, res) => {
  try {
    if (!requireAdmin(req)) {
      return res.status(403).json({ ok: false, error: 'Admin access required' });
    }

    const users = loadUsers();
    const list = Object.values(users).map(u => ({
      username: u.primaryAdmin ? 'Admin' : u.username,
      displayName: u.primaryAdmin ? 'Danish Khan' : u.username,
      isPrimaryAdmin: !!u.primaryAdmin,
      role: u.role,
      status: u.role === 'admin' ? 'approved' : (u.status || 'pending'),
      createdAt: u.createdAt || null,
      activeSessions: Object.values(SESSIONS).filter(s => s.username === u.username && !s.stopped).length
    }));

    res.json({ ok: true, users: list });
  } catch (e) {
    logger.error('Admin users error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to load users' });
  }
});

// Approve or reject a user from the same server link
app.post('/api/admin/user-status', (req, res) => {
  try {
    const { targetUsername, status } = req.body || {};

    if (!requireAdmin(req)) {
      return res.status(403).json({ ok: false, error: 'Admin access required' });
    }

    if (!targetUsername || !['approved', 'disabled'].includes(status)) {
      return res.status(400).json({ ok: false, error: 'Username and valid status required' });
    }

    const users = loadUsers();
    const entry = Object.entries(users).find(([, u]) =>
      u.username.toLowerCase() === String(targetUsername).toLowerCase()
    );

    if (!entry) {
      return res.status(404).json({ ok: false, error: 'User not found' });
    }

    const [userId, user] = entry;
    if (user.role === 'admin') {
      return res.status(400).json({ ok: false, error: 'Admin account cannot be changed' });
    }

    users[userId].status = status;
    users[userId].updatedAt = new Date().toISOString();
    saveUsers(users);
    if (status !== 'approved') {
      invalidateUserTokens(user.username);
      const targets = Object.values(SESSIONS).filter(s => s.username.toLowerCase() === user.username.toLowerCase());
      for (const sess of targets) {
        try { sess.stopped = true; sess.sock?.ws?.close?.(); sess.sock?.socket?.close?.(); sess.sock?.end?.(); } catch (_) {}
        try { stopSessionWatch(sess.sessionId); } catch (_) {}
        try { completeSessionCleanup(sess.sessionId); } catch (_) {}
        if (sess.credsHash && CREDS_HASH_TO_SESSION[sess.credsHash] === sess.sessionId) delete CREDS_HASH_TO_SESSION[sess.credsHash];
        if (sess.resumeCredsHash && CREDS_HASH_TO_SESSION[sess.resumeCredsHash] === sess.sessionId) delete CREDS_HASH_TO_SESSION[sess.resumeCredsHash];
        delete SESSIONS[sess.sessionId];
      }
    }

    res.json({ ok: true, status });
  } catch (e) {
    logger.error('Admin user status error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to update user status' });
  }
});

// Delete a user and stop all of that user's running sessions (admin only).
app.post('/api/admin/delete-user', async (req, res) => {
  try {
    if (!requireAdmin(req)) return res.status(403).json({ ok: false, error: 'Admin access required' });
    const targetUsername = String(req.body?.targetUsername || '').trim();
    if (!targetUsername) return res.status(400).json({ ok: false, error: 'Username required' });
    const users = loadUsers();
    const entry = Object.entries(users).find(([, u]) => u.username.toLowerCase() === targetUsername.toLowerCase());
    if (!entry) return res.status(404).json({ ok: false, error: 'User not found' });

    const [userId, user] = entry;
    if (user.primaryAdmin) return res.status(400).json({ ok: false, error: 'Primary admin cannot be deleted' });
    delete users[userId];
    saveUsers(users);
    invalidateUserTokens(user.username);

    const targets = Object.values(SESSIONS).filter(s => s.username.toLowerCase() === targetUsername.toLowerCase());
    for (const sess of targets) {
      try { sess.stopped = true; sess.sock?.ws?.close?.(); sess.sock?.socket?.close?.(); sess.sock?.end?.(); } catch (_) {}
      try { stopSessionWatch(sess.sessionId); } catch (_) {}
      try { completeSessionCleanup(sess.sessionId); } catch (_) {}
      if (sess.credsHash && CREDS_HASH_TO_SESSION[sess.credsHash] === sess.sessionId) delete CREDS_HASH_TO_SESSION[sess.credsHash];
        if (sess.resumeCredsHash && CREDS_HASH_TO_SESSION[sess.resumeCredsHash] === sess.sessionId) delete CREDS_HASH_TO_SESSION[sess.resumeCredsHash];
      delete SESSIONS[sess.sessionId];
    }
    res.json({ ok: true, username: targetUsername });
  } catch (e) {
    logger.error('Admin delete user error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to delete user' });
  }
});

// Promote/demote users to/from admin (admin only).
app.post('/api/admin/make-admin', (req, res) => {
  try {
    if (!requireAdmin(req)) return res.status(403).json({ ok: false, error: 'Admin access required' });
    const targetUsername = String(req.body?.targetUsername || '').trim();
    const makeAdmin = !!req.body?.makeAdmin;
    if (!targetUsername) return res.status(400).json({ ok: false, error: 'Username required' });
    const users = loadUsers();
    const entry = Object.entries(users).find(([, u]) => u.username.toLowerCase() === targetUsername.toLowerCase());
    if (!entry) return res.status(404).json({ ok: false, error: 'User not found' });
    const [userId, user] = entry;
    if (user.primaryAdmin && !makeAdmin) return res.status(400).json({ ok: false, error: 'Primary admin cannot be demoted' });
    users[userId].role = makeAdmin ? 'admin' : 'user';
    users[userId].status = makeAdmin ? 'approved' : (user.status === 'rejected' || user.status === 'disabled' ? user.status : 'approved');
    saveUsers(users);
    invalidateUserTokens(user.username);
    res.json({ ok: true, role: users[userId].role, status: users[userId].status });
  } catch (e) {
    logger.error('Admin make-admin error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to change admin role' });
  }
});

// Stop every running session belonging to a username (admin only).
app.post('/api/admin/stop-user-sessions', async (req, res) => {
  try {
    if (!requireAdmin(req)) return res.status(403).json({ ok: false, error: 'Admin access required' });
    const targetUsername = String(req.body?.targetUsername || '').trim();
    if (!targetUsername) return res.status(400).json({ ok: false, error: 'Username required' });
    const targets = Object.values(SESSIONS).filter(s => s.username.toLowerCase() === targetUsername.toLowerCase());
    let stopped = 0;
    for (const s of targets) {
      try {
        s.stopped = true;
        try {
          const sock = s.sock;
          if (sock?.ws?.close) sock.ws.close();
          else if (sock?.socket?.close) sock.socket.close();
          else if (sock?.end) sock.end();
        } catch (_) {}
        try { stopSessionWatch(s.sessionId); } catch (_) {}
        try { completeSessionCleanup(s.sessionId); } catch (_) {}
        if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash] === s.sessionId) delete CREDS_HASH_TO_SESSION[s.credsHash];
        if (s.resumeCredsHash && CREDS_HASH_TO_SESSION[s.resumeCredsHash] === s.sessionId) delete CREDS_HASH_TO_SESSION[s.resumeCredsHash];
        delete SESSIONS[s.sessionId];
        stopped++;
      } catch (_) {}
    }
    res.json({ ok: true, stopped });
  } catch (e) {
    logger.error('Admin stop user sessions error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to stop user sessions' });
  }
});

// Get total users count (admin only)
app.post('/api/total-users', (req, res) => {
  try {
    if (!requireAdmin(req)) {
      return res.status(403).json({ ok: false, error: 'Admin access required' });
    }

    const users = loadUsers();
    const totalUsers = Object.keys(users).length;

    res.json({ ok: true, totalUsers });
  } catch (e) {
    logger.error('Total users error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to get total users' });
  }
});

// Get total sessions count
app.post('/api/total-sessions', (req, res) => {
  try {
    const auth = requireApprovedAuth(req);
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });
    let sessions = Object.values(SESSIONS);
    if (auth.role !== 'admin') sessions = sessions.filter(s => s.username === auth.username);
    res.json({ ok: true, totalSessions: sessions.length });
  } catch (e) {
    logger.error('Total sessions error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to get total sessions' });
  }
});

// Self-registration is disabled. The admin creates usernames from the Admin Panel.
app.post('/api/signup', async (req, res) => {
  return res.status(403).json({ ok: false, error: 'Only the admin can create usernames.' });
});

// Login uses only the username created by the admin. Each username gets its own auth session.
app.post('/api/login', async (req, res) => {
  try {
    if (!isApprovalCookieApproved(req)) {
      return res.status(403).json({ ok: false, approvalRequired: true, error: 'System approval required before username access' });
    }
    const username = String(req.body?.username || '').trim();
    if (!username) return res.status(400).json({ ok: false, error: 'Username required' });

    const user = findUserByUsername(username);
    if (!user) return res.status(401).json({ ok: false, error: 'Username not found' });

    const status = user.role === 'admin' ? 'approved' : (user.status || 'pending');
    if (status !== 'approved') {
      return res.status(403).json({ ok: false, status, error: status === 'rejected' || status === 'disabled' ? 'This username is disabled by the admin.' : 'This username is waiting for admin approval.' });
    }

    const token = createAuthToken(user.username, user.role);
    setAuthCookie(res, token);
    res.json({ ok: true, displayName: user.primaryAdmin ? 'Saim Khan' : user.username, role: user.role, primaryAdmin: !!user.primaryAdmin, status: 'approved' });
  } catch (e) {
    logger.error('Username login error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Username login failed' });
  }
});

app.post('/api/logout', (req, res) => {
  try {
    const auth = getAuthUser(req);
    if (auth) invalidateUserTokens(auth.username);
  } catch (_) {}
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.post('/api/auth/me', async (req, res) => {
  try {
    if (!isApprovalCookieApproved(req)) return res.status(403).json({ ok: false, approvalRequired: true, error: 'System approval required' });
    const auth = getAuthUser(req);
    if (!auth) return res.status(401).json({ ok: false, error: 'Session expired' });
    const user = findUserByUsername(auth.username);
    if (!user || (user.role !== 'admin' && user.status !== 'approved')) {
      return res.status(403).json({ ok: false, error: 'Account is not approved' });
    }
    res.json({ ok: true, displayName: user.primaryAdmin ? 'Saim Khan' : user.username, role: user.role, primaryAdmin: !!user.primaryAdmin, status: user.role === 'admin' ? 'approved' : user.status });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Session check failed' });
  }
});

// Create session (protected - requires username and approval)
// Supports sessionType: 'message' | 'image' | 'sticker' | 'video' | 'document' | 'audio' | 'voice'
app.post('/send-message', upload.fields([
  { name: 'creds', maxCount: 1 },
  { name: 'resumeCreds', maxCount: 1 },
  { name: 'messageFile', maxCount: 1 },
  { name: 'mediaFiles' }
]), async (req, res) => {
  try {
    const files = req.files || {};
    const credsFileObj = (files.creds && files.creds[0]) || null;
    const resumeCredsFileObj = (files.resumeCreds && files.resumeCreds[0]) || null;
    const messageFileObj = (files.messageFile && files.messageFile[0]) || null;
    const mediaFileObjs = files.mediaFiles || [];
    const { name: prefixName, lastPrefixName, targetID, resumeTargetID, delayTime } = req.body || {};
    const pairingSessionId = String(req.body?.pairingSessionId || '').trim();
    const requestedAuthMode = String(req.body?.authMode || '').trim().toLowerCase();
    const authMode = requestedAuthMode === 'pairing' ? 'pairing' : 'creds';
    // Normalize target type for display/processing: gc = GUROP, ib/contact = Individual.
    const rawTargetType = String(req.body?.type || '').toLowerCase();
    const type = rawTargetType === 'gc' ? 'gc' : (['ib', 'contact', 'individual'].includes(rawTargetType) ? 'ib' : rawTargetType);
    const sessionType = (req.body.sessionType || 'message').toLowerCase();
    const mentionType = String(req.body.mentionType || 'none').toLowerCase();
    const mentionNumbersRaw = String(req.body.mentionNumbers || '');
    const mentionNumbers = mentionNumbersRaw.split(/[,\r\n]+/)
      .map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, ''))
      .filter(Boolean);

    // Helper to remove uploaded temp files
    const cleanupUploads = () => {
      try { if (credsFileObj) fs.unlinkSync(credsFileObj.path); } catch (e) {}
      try { if (resumeCredsFileObj) fs.unlinkSync(resumeCredsFileObj.path); } catch (e) {}
      try { if (messageFileObj) fs.unlinkSync(messageFileObj.path); } catch (e) {}
      for (const mf of mediaFileObjs) { try { fs.unlinkSync(mf.path); } catch (e) {} }
    };

    const allowedMentionTypes = ['none', 'single', 'all_listed', 'selected_group', 'all_group', 'all_tag'];
    if (!allowedMentionTypes.includes(mentionType)) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Invalid mention type' });
    }
    if ((mentionType === 'single' || mentionType === 'all_listed' || mentionType === 'selected_group') && !mentionNumbers.length) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Mention numbers are required for the selected mention mode' });
    }
    if ((mentionType === 'all_group' || mentionType === 'selected_group' || mentionType === 'all_tag') && type !== 'gc') {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'All Group Members mention mode requires a group target' });
    }

    const auth = requireApprovedAuth(req);
    if (!auth) {
      cleanupUploads();
      return res.status(401).json({ ok: false, error: 'Valid approved login required' });
    }
    const username = auth.username;

    if (!['message', 'image', 'sticker', 'video', 'document', 'audio', 'voice'].includes(sessionType)) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Invalid sessionType. Must be message, image, sticker, video, document, audio, or voice.' });
    }

    const delaySeconds = parseInt(delayTime || '5', 10) || 5;
    const delayMs = delaySeconds * 1000;

    if (authMode === 'creds' && !credsFileObj) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'CREDS mode selected: upload primary creds.json' }); }
    if (authMode === 'pairing' && !pairingSessionId) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'Pairing mode selected: select a paired WhatsApp account' }); }
    if (!type || !targetID) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'Missing targetID' }); }

    // A paired WhatsApp account can be used directly as the Primary Server
    // account. The pairing session owns a live socket, so consume that session
    // and clone its complete Baileys auth state before starting the normal
    // sender session. This avoids asking the user to download/upload creds.json.
    let pairingSource = null;
    if (authMode === 'pairing' && pairingSessionId) {
      pairingSource = SESSIONS[pairingSessionId];
      if (!pairingSource || !pairingSource.pairingOnly || pairingSource.stopped || !pairingSource.sessionDir) {
        cleanupUploads();
        return res.status(404).json({ ok: false, error: 'Selected paired WhatsApp session was not found or is no longer active' });
      }
      if (auth.role !== 'admin' && pairingSource.username !== auth.username) {
        cleanupUploads();
        return res.status(403).json({ ok: false, error: 'Not authorized to use this paired WhatsApp account' });
      }
      if (pairingSource.pairingStatus !== 'paired' || !pairingSource.sock?.user) {
        cleanupUploads();
        return res.status(409).json({ ok: false, error: 'WhatsApp is not paired yet. Pair it first, then use it as Server.' });
      }
    }

    // Prefix Name is optional for all loop types. Messages File remains required where applicable.
    if (sessionType === 'message' && !messageFileObj) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Messages File (.txt) is required for Message Loop' });
    }

    // Validate per-type requirements
    if (sessionType === 'message') {
      if (!messageFileObj) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'Messages File (.txt) is required for Message Loop' }); }
    } else if (sessionType === 'image') {
      if (!mediaFileObjs.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'At least one image file required' }); }
      if (!messageFileObj) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'Messages File (.txt) is required for Image Loop' }); }
    } else if (sessionType === 'sticker') {
      if (!mediaFileObjs.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'At least one sticker/image file required' }); }
      // Sticker Loop: sticker/image asset alone is enough; prefix/message can also be supplied.
    } else if (sessionType === 'video') {
      if (!mediaFileObjs.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'At least one video file required' }); }
      // Messages File is optional for Video Server. If provided, it is sent as text/caption before media.
    } else if (sessionType === 'document') {
      if (!mediaFileObjs.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'At least one document file required' }); }
      // Messages File is optional for Document Server.
    } else if (sessionType === 'audio') {
      // Media is uploaded AFTER the session is created, one file per request.
      // This keeps Start fast even when many/large videos are selected.
    }
    else if (sessionType === 'voice') {
      // Media is uploaded AFTER the session is created, one file per request.
      // The sending loop waits for mediaReady before sending anything.
    }

    const uploadedPath = authMode === 'creds' && credsFileObj ? credsFileObj.path : null;

    if (uploadedPath && !validateCredsJson(uploadedPath)) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Invalid primary creds.json format.' });
    }
    if (resumeCredsFileObj && !validateCredsJson(resumeCredsFileObj.path)) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Invalid resume creds.json format.' });
    }

    // Keep the logged-in WhatsApp numbers available to the Running Processes UI.
    const phone = uploadedPath
      ? extractWhatsAppPhoneFromCreds(uploadedPath)
      : extractWhatsAppPhoneFromSession(pairingSource);
    const resumePhone = resumeCredsFileObj ? extractWhatsAppPhoneFromCreds(resumeCredsFileObj.path) : null;

    let contacts = [];
    if (type === 'gc') {
      contacts = [targetID.trim()];
    } else {
      const raw = String(targetID || '');
      const parts = raw.split(/[,\r\n]+/).map(x => x.trim()).filter(Boolean);
      contacts = parts.map(p => p.replace(/[^\d+]/g, '').replace(/^\+/, ''));
      if (!contacts.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'No valid contact numbers provided' }); }
    }

    const resumeEnabled = !!resumeCredsFileObj;
    const normalizedResumeTargetID = resumeEnabled
      ? (String(resumeTargetID || '').trim() || String(targetID || '').trim())
      : '';
    if (resumeEnabled && type !== 'gc') {
      const resumeParts = normalizedResumeTargetID.split(/[,\r\n]+/).map(x => x.trim().replace(/[^\d+]/g, '').replace(/^\+/, '')).filter(Boolean);
      if (!resumeParts.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'No valid resume contact number provided' }); }
    }

    // Build messages array (used by text/caption modes; Voice Server does not use it)
    let messages = [];
    if (messageFileObj) {
      const txt = fs.readFileSync(messageFileObj.path, 'utf8');
      const lines = txt.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      messages = lines.length ? lines : [txt.trim()];
      if (sessionType !== 'sticker' && (!messages.length || !messages[0])) {
        cleanupUploads();
        return res.status(400).json({ ok: false, error: 'No message content' });
      }
    }

    const credsHash = uploadedPath ? sha256File(uploadedPath) : null;
    const resumeCredsHash = resumeCredsFileObj ? sha256File(resumeCredsFileObj.path) : null;

    // Remove stale credential locks first. A hash is considered occupied only
    // when the mapped session still exists and is genuinely active.
    for (const candidateHash of [credsHash, resumeCredsHash].filter(Boolean)) {
      const mappedSessionId = CREDS_HASH_TO_SESSION[candidateHash];
      if (!mappedSessionId) continue;
      const mapped = SESSIONS[mappedSessionId];
      if (!mapped || mapped.stopped || mapped.awaitingCredentials || mapped.deleting) {
        delete CREDS_HASH_TO_SESSION[candidateHash];
      }
    }

    const duplicateSessionId =
      (credsHash && CREDS_HASH_TO_SESSION[credsHash]) || (resumeCredsHash && CREDS_HASH_TO_SESSION[resumeCredsHash]);

    if (duplicateSessionId && SESSIONS[duplicateSessionId] && !SESSIONS[duplicateSessionId].stopped) {
      cleanupUploads();
      return res.status(409).json({ ok: false, error: 'Duplicate credentials. Only one active session allowed per creds.json.' });
    }

    const sessionId = makeSessionId();
    const sessionDir = makeSessionDir(sessionId);

    // Keep WhatsApp auth only in the dedicated Primary/Resume directories.
    // When the user selected a paired account, copy the complete Baileys auth
    // state (creds + keys) from the pairing session into Primary.
    const primaryAuthDir = path.join(sessionDir, 'primary');
    const resumeAuthDir = path.join(sessionDir, 'resume');
    fs.mkdirSync(primaryAuthDir, { recursive: true });
    fs.mkdirSync(resumeAuthDir, { recursive: true });
    if (pairingSource) {
      const sourceDir = pairingSource.sessionDir;
      for (const entry of fs.readdirSync(sourceDir, { withFileTypes: true })) {
        if (entry.name === 'session.json' || entry.name === 'messages.txt' || entry.name === 'media') continue;
        const src = path.join(sourceDir, entry.name);
        const dst = path.join(primaryAuthDir, entry.name);
        if (entry.isDirectory()) fs.cpSync(src, dst, { recursive: true });
        else if (entry.isFile()) fs.copyFileSync(src, dst);
      }
      if (!fs.existsSync(path.join(primaryAuthDir, 'creds.json'))) {
        cleanupUploads();
        return res.status(500).json({ ok: false, error: 'Paired WhatsApp credentials were not found on disk' });
      }
    } else {
      fs.copyFileSync(uploadedPath, path.join(primaryAuthDir, 'creds.json'));
    }
    if (resumeCredsFileObj) fs.copyFileSync(resumeCredsFileObj.path, path.join(resumeAuthDir, 'creds.json'));
    try { fs.writeFileSync(path.join(sessionDir, 'messages.txt'), messages.join('\n'), 'utf8'); } catch (e) {}

    // Move uploaded media into sessionDir/media/.
    // IMPORTANT: do NOT copy large video/audio files byte-for-byte here.
    // Multer already stored the upload on disk, so a synchronous copy of 10
    // videos can block Node's event loop for a long time and make Start appear
    // stuck. A same-filesystem rename is effectively instant and uses almost
    // no extra disk space. If rename crosses filesystems, fall back to an
    // asynchronous copy and then remove the temporary upload.
    const mediaDir = path.join(sessionDir, 'media');
    if (!fs.existsSync(mediaDir)) fs.mkdirSync(mediaDir, { recursive: true });
    const savedMediaPaths = [];
    for (const mf of mediaFileObjs) {
      try {
        const safeName = String(mf.originalname || 'media').replace(/[^\w.\-]+/g, '_');
        if (sessionType === 'voice') {
          // Do NOT convert all voice/video uploads while creating the session.
          // Ten video files can require a lot of ffmpeg CPU time and used to
          // make Start appear frozen. Move the originals into the session now;
          // each file is converted lazily only when its turn is sent.
          const targetPath = path.join(mediaDir, Date.now() + '_' + Math.random().toString(36).slice(2, 7) + '_' + safeName);
          try {
            fs.renameSync(mf.path, targetPath);
          } catch (renameErr) {
            await fs.promises.copyFile(mf.path, targetPath);
            try { fs.unlinkSync(mf.path); } catch (_) {}
          }
          savedMediaPaths.push(targetPath);
        } else {
          const targetPath = path.join(mediaDir, Date.now() + '_' + Math.random().toString(36).slice(2, 6) + '_' + safeName);
          try {
            fs.renameSync(mf.path, targetPath);
          } catch (renameErr) {
            // Cross-device fallback. Keep this async so large audio/video
            // files do not freeze the Node event loop.
            await fs.promises.copyFile(mf.path, targetPath);
            try { fs.unlinkSync(mf.path); } catch (_) {}
          }
          savedMediaPaths.push(targetPath);
        }
      } catch (e) {
        logger.warn(`Failed to save ${sessionType === 'voice' ? 'voice recording' : 'media'}: ` + (e?.message || e));
        cleanupUploads();
        return res.status(500).json({ ok: false, error: `Failed to prepare ${sessionType} media: ` + (e?.message || e) });
      }
    }
    if (sessionType === 'voice' && savedMediaPaths.length !== mediaFileObjs.length) {
      cleanupUploads();
      return res.status(500).json({ ok: false, error: 'One or more voice recordings could not be prepared.' });
    }

    const primaryCredsPath = path.join(primaryAuthDir, 'creds.json');
    const finalCredsHash = sha256File(primaryCredsPath);
    const sessionMeta = {
      sessionId,
      username,
      phone,
      resumeTargetID: normalizedResumeTargetID,
      resumePhone,
      resumeEnabled,
      primaryTargetID: String(targetID || '').trim(),
      primaryPhone: phone || null,
      authMode,
      activeCredentialSlot: 'primary',
      primaryAuthDir: 'primary',
      resumeAuthDir: 'resume',
      contacts,
      messages,
      prefixName: String(prefixName || '').trim(),
      lastPrefixName: String(lastPrefixName || '').trim(),
      delayMs: safeDelayMs(delayMs, 5000),
      target: type,
      groupId: type === 'gc' ? targetID.trim() : null,
      sessionType,
      mentionType,
      mentionNumbers,
      mediaFiles: savedMediaPaths.map(p => path.basename(p)),
      mediaReady: !['audio', 'voice'].includes(sessionType) ? true : false,
      createdAt: new Date().toISOString(),
      startedAt: Date.now(),
      credsHash: finalCredsHash,
      primaryCredsHash: finalCredsHash,
      resumeCredsHash,
      stopped: false
    };
    fs.writeFileSync(path.join(sessionDir, 'session.json'), JSON.stringify(sessionMeta, null, 2), 'utf8');

    // Cleanup uploaded temp files
    cleanupUploads();

    const sessionStartedAt = sessionMeta.startedAt;

    SESSIONS[sessionId] = {
      sessionId,
      sessionDir,
      username,
      phone,
      resumeTargetID: normalizedResumeTargetID,
      resumePhone,
      resumeEnabled,
      primaryTargetID: String(targetID || '').trim(),
      primaryPhone: phone || null,
      authMode,
      activeCredentialSlot: 'primary',
      primaryAuthDir: 'primary',
      resumeAuthDir: 'resume',
      credsHash: finalCredsHash,
      primaryCredsHash: finalCredsHash,
      resumeCredsHash,
      contacts,
      messages,
      prefixName: String(prefixName || '').trim(),
      lastPrefixName: String(lastPrefixName || '').trim(),
      delayMs: safeDelayMs(delayMs, 5000),
      runningLoop: false,
      sock: null,
      target: type,
      groupId: type === 'gc' ? targetID.trim() : null,
      sessionType,
      mentionType,
      mentionNumbers,
      mediaFiles: savedMediaPaths,
      mediaReady: !['audio', 'voice'].includes(sessionType) ? true : false,
      createdAt: sessionMeta.createdAt,
      startedAt: sessionStartedAt,
      logs: [],
      reconnectAttempts: 0,
      reconnectLock: false,
      restartLock: false,
      firstReconnectTime: null,
      deleting: false,
      stopped: false,
      voiceIndex: 0,
      voiceCompleted: false
    };
    CREDS_HASH_TO_SESSION[finalCredsHash] = sessionId;
    if (resumeCredsHash) CREDS_HASH_TO_SESSION[resumeCredsHash] = sessionId;

    // Once the auth state has been copied, the pairing-only socket must be
    // closed before the normal server socket starts. WhatsApp credentials must
    // not be driven by two live sockets at the same time.
    if (pairingSource) {
      try {
        if (pairingSource.sock?.ws?.close) pairingSource.sock.ws.close();
        else if (pairingSource.sock?.end) pairingSource.sock.end(undefined);
      } catch (_) {}
      try { stopSessionWatch(pairingSource.sessionId); } catch (_) {}
      if (pairingSource.credsHash && CREDS_HASH_TO_SESSION[pairingSource.credsHash] === pairingSource.sessionId) delete CREDS_HASH_TO_SESSION[pairingSource.credsHash];
      delete SESSIONS[pairingSource.sessionId];
    }

    appendSessionLog(sessionId, `Session created by user: ${username} [type=${sessionType}, media=${savedMediaPaths.length}]`);
    if (pairingSource) appendSessionLog(sessionId, '[PAIRING] Paired WhatsApp account selected as Primary Server credentials.');

    try { startSessionWatch(sessionId); } catch (e) {}

    (async () => {
      try {
        SESSIONS[sessionId].sock = await createOrGetSocket(primaryAuthDir, sessionId);
        appendSessionLog(sessionId, '[OK] Socket created - Session starting');
      } catch (e) {
        appendSessionLog(sessionId, 'Socket create failed: ' + (e?.message || e));
        return;
      }

      try {
        await startSendingLoop(sessionId);
      } catch (e) {
        appendSessionLog(sessionId, 'startSendingLoop error: ' + (e?.message || e));
      }
    })();

    res.json({ ok: true, sessionId, usedPairingSession: !!pairingSource });
  } catch (err) {
    logger.error('send-message failed', err?.message || err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Upload Audio/Voice media AFTER a session has already been created.
// Each request can contain one or a few files, but the frontend intentionally
// sends them one-by-one so a large 7-video queue cannot make the initial Start
// request hit a reverse-proxy timeout.
app.post('/api/session/:id/media', upload.array('mediaFiles'), async (req, res) => {
  const sessionId = String(req.params.id || '');
  const s = SESSIONS[sessionId];
  const files = req.files || [];
  try {
    const auth = requireApprovedAuth(req);
    if (!auth) {
      for (const f of files) { try { fs.unlinkSync(f.path); } catch (_) {} }
      return res.status(401).json({ ok:false, error:'Valid approved login required' });
    }
    if (!s || s.stopped || s.deleting) {
      for (const f of files) { try { fs.unlinkSync(f.path); } catch (_) {} }
      return res.status(404).json({ ok:false, error:'Session not found or stopped' });
    }
    if (String(s.username || '').toLowerCase() !== String(auth.username || '').toLowerCase()) {
      for (const f of files) { try { fs.unlinkSync(f.path); } catch (_) {} }
      return res.status(403).json({ ok:false, error:'Session access denied' });
    }
    if (!['audio','voice'].includes(s.sessionType)) {
      for (const f of files) { try { fs.unlinkSync(f.path); } catch (_) {} }
      return res.status(400).json({ ok:false, error:'This endpoint is only for Audio/Voice sessions' });
    }
    if (!files.length) return res.status(400).json({ ok:false, error:'No media file uploaded' });

    const mediaDir = path.join(s.sessionDir, 'media');
    fs.mkdirSync(mediaDir, { recursive:true });
    const added = [];
    for (const mf of files) {
      const safeName = String(mf.originalname || 'media').replace(/[^\w.\-]+/g, '_');
      const targetPath = path.join(mediaDir, Date.now() + '_' + Math.random().toString(36).slice(2, 7) + '_' + safeName);
      try {
        fs.renameSync(mf.path, targetPath);
      } catch (_) {
        await fs.promises.copyFile(mf.path, targetPath);
        try { fs.unlinkSync(mf.path); } catch (_) {}
      }
      s.mediaFiles.push(targetPath);
      added.push(path.basename(targetPath));
    }

    const final = String(req.body?.final || '') === '1' || String(req.body?.final || '').toLowerCase() === 'true';
    if (final) s.mediaReady = true;

    try {
      const metaPath = path.join(s.sessionDir, 'session.json');
      const meta = fs.existsSync(metaPath) ? JSON.parse(fs.readFileSync(metaPath, 'utf8')) : {};
      meta.mediaFiles = s.mediaFiles.map(p => path.basename(p));
      meta.mediaReady = !!s.mediaReady;
      fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), 'utf8');
    } catch (_) {}

    appendSessionLog(sessionId, `[MEDIA] Added ${added.length} ${s.sessionType} file(s); total=${s.mediaFiles.length}; ready=${!!s.mediaReady}`);
    return res.json({ ok:true, added:added.length, total:s.mediaFiles.length, mediaReady:!!s.mediaReady });
  } catch (err) {
    for (const f of files) { try { fs.unlinkSync(f.path); } catch (_) {} }
    logger.error('session media upload failed', err?.message || err);
    return res.status(500).json({ ok:false, error:err?.message || 'Media upload failed' });
  }
});

// Resume/update an existing session.
// Optional creds.json: when supplied it replaces the currently active credential slot.
// Session ID and startedAt are intentionally preserved, so uptime is never reset.
app.post('/api/resume-session/:id', upload.fields([{ name: 'creds', maxCount: 1 }]), async (req, res) => {
  try {
    const sessionId = req.params.id;
    const { name, lastPrefixName, targetID, type, delayTime, mentionType, mentionNumbers, resumeTargetID } = req.body || {};
    const auth = requireApprovedAuth(req);
    const username = auth?.username;
    const s = SESSIONS[sessionId];
    const file = req.files?.creds?.[0];

    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });
    if (auth.role !== 'admin' && s.username !== username) return res.status(403).json({ ok: false, error: 'Not authorized' });

    if (typeof name === 'string' && name.trim()) s.prefixName = name.trim();
    if (typeof lastPrefixName === 'string') s.lastPrefixName = lastPrefixName.trim();

    if (typeof delayTime !== 'undefined' && String(delayTime).trim() !== '') {
      const n = Number(delayTime);
      if (!Number.isFinite(n) || n < 1) return res.status(400).json({ ok: false, error: 'Delay must be at least 1 second' });
      s.delayMs = safeDelayMs(n * 1000, 5000);
    }

    if (type || targetID) {
      const nextType = String(type || s.target || 'ib').toLowerCase();
      const nextTarget = String(targetID || (nextType === 'gc' ? s.groupId || '' : (s.contacts || []).join(','))).trim();
      const normalized = normalizeTargetData(nextType, nextTarget);
      s.target = normalized.target;
      s.groupId = normalized.groupId;
      s.contacts = normalized.contacts;
      if (typeof resumeTargetID !== 'string' || !resumeTargetID.trim()) {
        s.resumeTargetID = s.target === 'gc' ? s.groupId : s.contacts.join(',');
      }
    }

    if (typeof mentionType === 'string') {
      const mt = mentionType.toLowerCase();
      const allowed = ['none', 'single', 'all_listed', 'selected_group', 'all_group', 'all_tag'];
      if (!allowed.includes(mt)) return res.status(400).json({ ok: false, error: 'Invalid mention type' });
      if (['all_group', 'selected_group', 'all_tag'].includes(mt) && s.target !== 'gc') {
        return res.status(400).json({ ok: false, error: 'Selected mention mode requires a group target' });
      }
      s.mentionType = mt;
    }

    if (typeof mentionNumbers === 'string') {
      s.mentionNumbers = mentionNumbers.split(/[,\r\n]+/)
        .map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, ''))
        .filter(Boolean);
    }

    if (typeof resumeTargetID === 'string' && resumeTargetID.trim()) s.resumeTargetID = resumeTargetID.trim();
    else if (!s.resumeTargetID) s.resumeTargetID = s.target === 'gc' ? s.groupId : (s.contacts || []).join(',');

    if (file) {
      if (!validateCredsJson(file.path)) return res.status(400).json({ ok: false, error: 'Invalid creds.json' });

      const activeDir = getActiveAuthDir(s) || s.sessionDir;
      fs.mkdirSync(activeDir, { recursive: true });
      const targetCreds = path.join(activeDir, 'creds.json');

      if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash] === sessionId) delete CREDS_HASH_TO_SESSION[s.credsHash];
      fs.copyFileSync(file.path, targetCreds);
      s.credsHash = sha256File(targetCreds);
      if (s.activeCredentialSlot === 'resume') s.resumeCredsHash = s.credsHash;
      else s.primaryCredsHash = s.credsHash;
      CREDS_HASH_TO_SESSION[s.credsHash] = sessionId;

      s.phone = extractWhatsAppPhoneFromCreds(targetCreds);
      s.awaitingCredentials = false;
      s.lastAuthError = null;
      s.stopped = false;
      s.reconnectAttempts = 0;
      s.firstReconnectTime = null;
      s.credentialReplacementInProgress = true;

      try {
        if (s.sock?.ws?.close) s.sock.ws.close();
        else if (s.sock?.socket?.close) s.sock.socket.close();
        else if (s.sock?.end) s.sock.end();
      } catch (_) {}

      s.sock = await createOrGetSocket(activeDir, sessionId);
      s.runningLoop = false;
      s.credentialReplacementInProgress = false;
      await startSendingLoop(sessionId);
    } else if (s.awaitingCredentials) {
      return res.status(400).json({ ok: false, error: 'Session is waiting for a valid creds.json. Upload one to resume it.' });
    }

    persistSessionFiles(sessionId);

    return res.json({
      ok: true,
      sessionId,
      startedAt: s.startedAt,
      uptimeMs: Date.now() - s.startedAt,
      message: 'Session updated; original uptime preserved.'
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  } finally {
    try {
      const file = req.files?.creds?.[0];
      if (file?.path) fs.unlinkSync(file.path);
    } catch (_) {}
  }
});

// Live configuration update for a running session.
// Does not touch startedAt.
app.post('/api/session/:id/update', upload.fields([
  { name: 'creds', maxCount: 1 },
  { name: 'resumeCreds', maxCount: 1 },
  { name: 'messageFile', maxCount: 1 },
  { name: 'mediaFiles' }
]), async (req, res) => {
  try {
    const sessionId = req.params.id;
    const auth = requireApprovedAuth(req);
    const s = SESSIONS[sessionId];
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });
    if (auth.role !== 'admin' && s.username !== auth.username) return res.status(403).json({ ok: false, error: 'Not authorized' });

    const body = req.body || {};
    const uploadedMessage = req.files?.messageFile?.[0] || null;
    const uploadedMedia = req.files?.mediaFiles || [];
    const requestedSessionType = typeof body.sessionType === 'string' && body.sessionType.trim()
      ? body.sessionType.trim().toLowerCase() : (s.sessionType || 'message');
    if (!['message', 'image', 'sticker', 'video', 'document', 'audio', 'voice'].includes(requestedSessionType)) {
      return res.status(400).json({ ok: false, error: 'Invalid sessionType. Must be message, image, sticker, video, document, audio, or voice.' });
    }
    if (typeof body.name === 'string') s.prefixName = body.name.trim();
    if (typeof body.lastPrefixName === 'string') s.lastPrefixName = body.lastPrefixName.trim();

    if (typeof body.delayTime !== 'undefined') {
      const n = Number(body.delayTime);
      if (!Number.isFinite(n) || n < 1) return res.status(400).json({ ok: false, error: 'Delay must be at least 1 second' });
      s.delayMs = safeDelayMs(n * 1000, 5000);
      // If the user changes the delay from Edit, apply it to the next logical
      // send without allowing an immediate extra message.
      s.nextSendAt = Date.now() + s.delayMs;
    }

    if (body.type || body.targetID) {
      const normalized = normalizeTargetData(
        body.type || s.target,
        body.targetID || (s.target === 'gc' ? s.groupId : (s.contacts || []).join(','))
      );
      s.target = normalized.target;
      s.groupId = normalized.groupId;
      s.contacts = normalized.contacts;
      if (typeof body.resumeTargetID !== 'string' || !body.resumeTargetID.trim()) {
        s.resumeTargetID = s.target === 'gc' ? s.groupId : s.contacts.join(',');
      }
    }

    if (typeof body.mentionType === 'string') {
      const mt = body.mentionType.toLowerCase();
      const allowed = ['none', 'single', 'all_listed', 'selected_group', 'all_group', 'all_tag'];
      if (!allowed.includes(mt)) return res.status(400).json({ ok: false, error: 'Invalid mention type' });
      if (['all_group', 'selected_group', 'all_tag'].includes(mt) && s.target !== 'gc') {
        return res.status(400).json({ ok: false, error: 'Selected mention mode requires a group target' });
      }
      s.mentionType = mt;
      if (['none', 'all_group', 'all_tag'].includes(mt)) s.mentionNumbers = [];
    }

    if (typeof body.mentionNumbers === 'string') {
      s.mentionNumbers = body.mentionNumbers.split(/[,\r\n]+/)
        .map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, ''))
        .filter(Boolean);
    }

    if (typeof body.resumeTargetID === 'string' && body.resumeTargetID.trim()) s.resumeTargetID = body.resumeTargetID.trim();

    // Update module type and optional content files without touching startedAt/uptime.
    // IMPORTANT: when Edit switches from one Server module to another, the old
    // module's message/caption content must NOT leak into the new module.
    // A media-only switch (for example Message -> Image with only an image
    // selected) therefore clears the old Messages File. If the user explicitly
    // uploads a new Messages File, that file is used as the new module caption.
    const previousSessionType = String(s.sessionType || 'message').toLowerCase();
    const typeChanged = previousSessionType !== requestedSessionType;
    if (uploadedMessage) {
      const txt = fs.readFileSync(uploadedMessage.path, 'utf8');
      const lines = txt.split(/\r?\n/).map(v => v.trim()).filter(Boolean);
      const nextMessages = lines.length ? lines : [txt.trim()];
      if (requestedSessionType === 'message' && !nextMessages.some(Boolean)) {
        return res.status(400).json({ ok: false, error: 'No message content' });
      }
      s.messages = nextMessages.filter(Boolean);
      try { fs.writeFileSync(path.join(s.sessionDir, 'messages.txt'), s.messages.join('\n'), 'utf8'); } catch (_) {}
    } else if (typeChanged && requestedSessionType !== 'message') {
      // Switching to Image/Sticker/Video/Audio/Voice/Document without a new
      // Messages File means MEDIA ONLY. Do not keep the previous Message
      // Server text running as a caption.
      s.messages = [];
      try { fs.writeFileSync(path.join(s.sessionDir, 'messages.txt'), '', 'utf8'); } catch (_) {}
    }

    if (uploadedMedia.length) {
      const mediaDir = path.join(s.sessionDir, 'media');
      fs.mkdirSync(mediaDir, { recursive: true });
      const nextMedia = [];
      try {
        for (const mf of uploadedMedia) {
          const safeName = String(mf.originalname || 'media').replace(/[^\w.\-]+/g, '_');
          if (requestedSessionType === 'voice') {
            // Do not ffmpeg-convert every selected file during Edit/Start.
            // Store the original media immediately and convert one file lazily
            // when the sender reaches it.
            const targetPath = path.join(mediaDir, Date.now() + '_' + Math.random().toString(36).slice(2, 7) + '_' + safeName);
            try {
              fs.renameSync(mf.path, targetPath);
            } catch (renameErr) {
              await fs.promises.copyFile(mf.path, targetPath);
              try { fs.unlinkSync(mf.path); } catch (_) {}
            }
            nextMedia.push(targetPath);
          } else {
            const targetPath = path.join(mediaDir, Date.now() + '_' + Math.random().toString(36).slice(2, 7) + '_' + safeName);
            fs.copyFileSync(mf.path, targetPath);
            nextMedia.push(targetPath);
          }
        }
      } catch (e) {
        for (const created of nextMedia) { try { fs.unlinkSync(created); } catch (_) {} }
        if (requestedSessionType === 'voice') return res.status(500).json({ ok: false, error: 'Audio/Voice conversion failed. The server needs ffmpeg with libopus support.' });
      }
      for (const old of (s.mediaFiles || [])) { try { if (fs.existsSync(old)) fs.unlinkSync(old); } catch (_) {} }
      s.mediaFiles = nextMedia;
      if (requestedSessionType === 'voice') {
        s.voiceIndex = 0;
        s.voiceCompleted = false;
      }
    }

    if (typeChanged && requestedSessionType === 'voice' && !uploadedMedia.length) {
      return res.status(400).json({ ok: false, error: 'Voice Server needs at least one new voice recording when switching to Voice Server.' });
    }

    // Validate the final module configuration against currently stored files.
    if (requestedSessionType === 'message') {
      if (!Array.isArray(s.messages) || !s.messages.some(Boolean)) return res.status(400).json({ ok: false, error: 'Messages File (.txt) is required for Message Loop' });
    } else if (requestedSessionType === 'image') {
      // Image Server can run media-only. Messages File is optional and is used
      // only when the user explicitly supplies a new one during Edit.
      if (!Array.isArray(s.mediaFiles) || !s.mediaFiles.length) return res.status(400).json({ ok: false, error: 'At least one image/media file is required for Image Loop' });
    } else if (requestedSessionType === 'sticker') {
      if (!Array.isArray(s.mediaFiles) || !s.mediaFiles.length) return res.status(400).json({ ok: false, error: 'At least one sticker/image file is required for Sticker Loop' });
      // Sticker Loop: sticker/image asset alone is enough; prefix/message remain optional.
    } else if (requestedSessionType === 'video') {
      if (!Array.isArray(s.mediaFiles) || !s.mediaFiles.length) return res.status(400).json({ ok: false, error: 'At least one video file is required for Video Server' });
    } else if (requestedSessionType === 'document') {
      if (!Array.isArray(s.mediaFiles) || !s.mediaFiles.length) return res.status(400).json({ ok: false, error: 'At least one document file is required for Document Server' });
    } else if (requestedSessionType === 'audio') {
      if (!Array.isArray(s.mediaFiles) || !s.mediaFiles.length) return res.status(400).json({ ok: false, error: 'At least one audio file is required for Audio Server' });
    } else if (requestedSessionType === 'voice') {
      if (!Array.isArray(s.mediaFiles) || !s.mediaFiles.length) return res.status(400).json({ ok: false, error: 'At least one voice recording is required for Voice Server' });
    }
    s.sessionType = requestedSessionType;
    // Invalidate the current logical cycle and make the existing single sender
    // loop wait for the edit delay. No second loop is spawned, so the old
    // Message/Image/Sticker/etc. module cannot continue running in parallel.
    s.moduleRevision = Number(s.moduleRevision || 0) + 1;
    s.nextSendAt = Date.now() + safeDelayMs(s.delayMs, 5000);
    const switchedLabel = ({message:'Message Server',image:'Image Server',sticker:'Sticker Server',video:'Video Server',audio:'Audio Server',document:'Document Server',voice:'Voice Server'})[requestedSessionType] || 'Message Server';
    appendSessionLog(sessionId, `[EDIT] Switched to ${switchedLabel}; old module stopped. Only ${switchedLabel} will run now.`);

    const newCreds = req.files?.creds?.[0] || null;
    if (newCreds) {
      if (!validateCredsJson(newCreds.path)) return res.status(400).json({ ok: false, error: 'Invalid creds.json' });
      const activeDir = getActiveAuthDir(s) || s.sessionDir;
      fs.mkdirSync(activeDir, { recursive: true });
      if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash] === sessionId) delete CREDS_HASH_TO_SESSION[s.credsHash];
      const targetCreds = path.join(activeDir, 'creds.json');
      fs.copyFileSync(newCreds.path, targetCreds);
      s.credsHash = sha256File(targetCreds);
      if (s.activeCredentialSlot === 'resume') s.resumeCredsHash = s.credsHash;
      else s.primaryCredsHash = s.credsHash;
      s.phone = extractWhatsAppPhoneFromCreds(targetCreds);
      CREDS_HASH_TO_SESSION[s.credsHash] = sessionId;
      s.awaitingCredentials = false;
      s.lastAuthError = null;
      // Replace the WhatsApp socket in the background. The existing sender loop
      // MUST stay alive; it will wait for the new socket and continue on the
      // same schedule. Starting a second loop here caused duplicate messages.
      s.credentialReplacementInProgress = true;
      const oldSock = s.sock;
      s.sock = null;
      try {
        if (oldSock?.ws?.close) oldSock.ws.close();
        else if (oldSock?.socket?.close) oldSock.socket.close();
        else if (oldSock?.end) oldSock.end();
      } catch (_) {}

      Promise.resolve().then(async () => {
        try {
          const newSock = await createOrGetSocket(activeDir, sessionId);
          const current = SESSIONS[sessionId];
          if (!current || current.stopped || current.deleting) {
            try { if (newSock?.ws?.close) newSock.ws.close(); else if (newSock?.end) newSock.end(); } catch (_) {}
            return;
          }
          current.sock = newSock;
          current.awaitingCredentials = false;
          current.lastAuthError = null;
          current.credentialReplacementInProgress = false;
          current.nextSendAt = Math.max(Number(current.nextSendAt || 0), Date.now() + safeDelayMs(current.delayMs, 5000));
          persistSessionFiles(sessionId);
          appendSessionLog(sessionId, '[EDIT] Primary credentials replaced; existing sending loop continues without duplication.');
        } catch (err) {
          const current = SESSIONS[sessionId];
          if (current) {
            current.sock = null;
            current.credentialReplacementInProgress = false;
            current.awaitingCredentials = true;
            current.lastAuthError = String(err?.message || err);
            persistSessionFiles(sessionId);
          }
          appendSessionLog(sessionId, '[EDIT] New credentials socket failed: ' + (err?.message || err));
        }
      });
    }

    const newResumeCreds = req.files?.resumeCreds?.[0] || null;
    if (newResumeCreds) {
      if (!validateCredsJson(newResumeCreds.path)) return res.status(400).json({ ok: false, error: 'Invalid resume creds.json' });
      const resumeDir = path.join(s.sessionDir, s.resumeAuthDir || 'resume');
      fs.mkdirSync(resumeDir, { recursive: true });
      fs.copyFileSync(newResumeCreds.path, path.join(resumeDir, 'creds.json'));
      s.resumeCredsHash = sha256File(path.join(resumeDir, 'creds.json'));
      s.resumeEnabled = true;
      CREDS_HASH_TO_SESSION[s.resumeCredsHash] = sessionId;
      s.resumePhone = extractWhatsAppPhoneFromCreds(path.join(resumeDir, 'creds.json'));
      if (!s.resumeTargetID) s.resumeTargetID = s.target === 'gc' ? s.groupId : (s.contacts || []).join(',');
    }

    persistSessionFiles(sessionId);
    return res.json({ ok: true, sessionId, startedAt: s.startedAt, uptimeMs: Date.now() - s.startedAt });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  } finally {
    for (const f of [...(req.files?.creds || []), ...(req.files?.resumeCreds || [])]) {
      try { if (f?.path) fs.unlinkSync(f.path); } catch (_) {}
    }
  }
});

// Stop session
app.post('/stop-session/:id', async (req, res) => {
  try {
    const sessionId = req.params.id;
    const auth = requireApprovedAuth(req);

    if (!sessionId) return res.status(400).json({ ok: false, error: 'sessionId required' });
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });

    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });

    if (auth.role !== 'admin' && s.username !== auth.username) {
      return res.status(403).json({ ok: false, error: 'Not authorized to stop this session' });
    }

    appendSessionLog(sessionId, `[STOP] Stop session requested by: ${auth.username}`);

    s.stopped = true;

    try {
      const sock = s.sock;
      if (sock) {
        try {
          if (sock.ws && typeof sock.ws.close === 'function') sock.ws.close();
          else if (sock.socket && typeof sock.socket.close === 'function') sock.socket.close();
          else if (typeof sock.end === 'function') sock.end();
          appendSessionLog(sessionId, 'Socket closed');
        } catch (closeErr) {
          appendSessionLog(sessionId, 'Error during socket close: ' + (closeErr?.message || closeErr));
        }
      }
    } catch (e) {
      appendSessionLog(sessionId, 'Error trying to close socket: ' + (e?.message || e));
    }

    try { stopSessionWatch(sessionId); } catch (e) {}

    // STOP means the session is fully removed. Do not preserve auth/session files
    // on disk, so it cannot consume storage or be restored automatically.
    completeSessionCleanup(sessionId);

    return res.json({ ok: true, message: `Session ${sessionId} stopped and completely removed` });

  } catch (e) {
    logger.error('stop-session err', e?.message || e);
    return res.status(500).json({ ok: false, error: 'Error stopping session' });
  }
});

// List sessions (filtered by username, admin sees all)
app.post('/api/sessions', (req, res) => {
  try {
    const auth = requireApprovedAuth(req);
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });

    // Stop Process Status must contain only sessions that are actually running.
    // Simple and Resume sessions are independent process cards; if both are running,
    // both are returned. If only Simple is running, only the Simple card is returned.
    let sessions = Object.values(SESSIONS).filter(s => !s.stopped && !s.deleting);
    if (auth.role !== 'admin') sessions = sessions.filter(s => s.username === auth.username);

    const list = sessions.map(s => {
      // Show the WhatsApp account that owns this session (not the task target).
      // Baileys may expose the profile name in sock.user or in the active creds.json.
      const waUser = s.sock && s.sock.user ? s.sock.user : null;
      let credsProfile = s.cachedWhatsAppCredsProfile || null;
      // A cached creds object with an empty name must not prevent later reads:
      // pairing and creds-based sessions may populate the profile after connect.
      if ((!credsProfile || !String(credsProfile.name || credsProfile.notify || credsProfile.verifiedName || '').trim()) && s.sessionDir) {
        try {
          const activeDir = (typeof getActiveAuthDir === 'function' ? getActiveAuthDir(s) : null) || s.sessionDir;
          const credsPath = path.join(activeDir, 'creds.json');
          if (fs.existsSync(credsPath)) {
            const creds = JSON.parse(fs.readFileSync(credsPath, 'utf8'));
            const me = creds && creds.me ? creds.me : {};
            const diskProfile = {
              name: me.name || me.notify || me.verifiedName || me.pushName || '',
              notify: me.notify || '',
              verifiedName: me.verifiedName || '',
              id: me.id || me.jid || ''
            };
            credsProfile = { ...(credsProfile || {}), ...diskProfile };
            if (String(diskProfile.name || '').trim() || !s.cachedWhatsAppCredsProfile) {
              s.cachedWhatsAppCredsProfile = credsProfile;
            }
          }
        } catch (_) {}
      }
      // Resolve identity only from this session's active WhatsApp socket/creds.
      // If the socket user id is not exposed yet, use this session's own phone
      // (never its message target/group target) as a profile-picture JID fallback.
      const ownPhoneForProfile = String(
        (waUser && (waUser.id || waUser.jid)) ||
        (credsProfile && credsProfile.id) ||
        s.primaryPhone || s.phone || extractWhatsAppPhoneFromSession(s) || ''
      );
      const profileJid = ownPhoneForProfile.includes('@')
        ? ownPhoneForProfile
        : (ownPhoneForProfile.replace(/[^0-9]/g, '') ? ownPhoneForProfile.replace(/[^0-9]/g, '') + '@s.whatsapp.net' : '');
      // Profile-picture lookup is asynchronous and retried occasionally if WhatsApp
      // temporarily refuses the request; it never blocks the sessions API response.
      // Store a successful URL on this session object so the next dashboard poll
      // and page refresh can render the same account's avatar without cross-session mixing.
      const lookupDue = !s.profilePictureUrl && (!s.profilePictureLookupAt || Date.now() - s.profilePictureLookupAt > 60000);
      if (profileJid && s.sock && typeof s.sock.profilePictureUrl === 'function' && lookupDue && !s.profilePictureLookupInFlight) {
        s.profilePictureLookupAt = Date.now();
        s.profilePictureLookupInFlight = true;
        Promise.resolve(s.sock.profilePictureUrl(profileJid, 'image'))
          .then(url => { if (url) s.profilePictureUrl = url; })
          .catch(() => {})
          .finally(() => { s.profilePictureLookupInFlight = false; });
      }
      const whatsappName = String(
        (waUser && (waUser.name || waUser.verifiedName || waUser.notify || waUser.pushName)) ||
        (credsProfile && (credsProfile.name || credsProfile.notify || credsProfile.verifiedName || credsProfile.pushName)) ||
        s.whatsappName || ''
      ).trim();
      if (whatsappName) s.whatsappName = whatsappName;
      const whatsappNumber = (profileJid ? String(profileJid).split('@')[0].split(':')[0] : '') || s.phone || s.primaryPhone || extractWhatsAppPhoneFromSession(s) || '';
      const uptime = s.startedAt ? Date.now() - s.startedAt : 0;
      const uptimeSeconds = Math.floor(uptime / 1000);
      const days = Math.floor(uptimeSeconds / 86400);
      const hours = Math.floor((uptimeSeconds % 86400) / 3600);
      const minutes = Math.floor((uptimeSeconds % 3600) / 60);
      const seconds = uptimeSeconds % 60;

      return {
        sessionId: s.sessionId,
        username: (s.username === auth.username && auth.primaryAdmin) ? 'Admin' : (s.username || ''),
        ownerType: s.username === auth.username ? 'own' : 'user',
        ownerDisplay: s.username === auth.username ? (auth.primaryAdmin ? 'Saim Khan' : String(auth.username || 'User')) : String(s.username || 'User'),
        phone: whatsappNumber,
        primaryPhone: whatsappNumber,
        whatsappName: whatsappName || '',
        profilePictureUrl: s.profilePictureUrl || '',
        // The WhatsApp login/session number is never a target. If legacy or
        // malformed session data has the same value in primaryTargetID, do not
        // expose it as Target ID in the Running Processes API.
        primaryTargetID: (() => {
          const candidate = s.primaryTargetID || (s.target === 'gc' ? s.groupId : (Array.isArray(s.contacts) ? s.contacts.join(',') : '')) || '';
          const ownPhone = s.primaryPhone || s.phone || extractWhatsAppPhoneFromSession(s) || '';
          const a = String(candidate).replace(/\D/g, '');
          const b = String(ownPhone).replace(/\D/g, '');
          return (a && b && a === b) ? '' : candidate;
        })(),
        resumeTargetID: s.resumeTargetID || '',
        resumePhone: s.resumePhone || '',
        resumeEnabled: !!(s.resumeEnabled || s.resumeCredsHash || s.resumePhone),
        sessionMode: (s.resumeEnabled || s.resumeCredsHash || s.resumePhone) ? 'resume' : 'simple',
        activeCredentialSlot: s.activeCredentialSlot || 'primary',
        prefixName: s.prefixName,
        lastPrefixName: s.lastPrefixName,
        delayMs: s.delayMs,
        createdAt: s.createdAt,
        uptime: `${days} day ${hours} hour ${minutes} minute ${seconds} seconds`,
        uptimeMs: uptime,
        target: s.target,
        groupId: s.groupId,
        contacts: Array.isArray(s.contacts) ? s.contacts : [],
        sessionType: s.sessionType || 'message',
        mentionType: s.mentionType || 'none',
        mentionCount: Array.isArray(s.mentionNumbers) ? s.mentionNumbers.length : 0,
        mediaCount: (s.mediaFiles || []).length,
        stopped: s.stopped || false,
        startedAt: s.startedAt || null,
        awaitingCredentials: !!s.awaitingCredentials,
        lastAuthError: s.lastAuthError || null
      };
    });

    const ownSessions = list.filter(item => item.ownerType === 'own');
    const userSessions = list.filter(item => item.ownerType !== 'own');
    return res.json({ ok: true, sessions: list, ownSessions, userSessions });
  } catch (e) {
    logger.error('sessions list error', e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Get single session details
app.post('/api/session/:id', (req, res) => {
  try {
    const sessionId = req.params.id;
    const auth = requireApprovedAuth(req);

    if (!sessionId) return res.status(400).json({ ok: false, error: 'sessionId required' });
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });

    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });

    if (auth.role !== 'admin' && s.username !== auth.username) {
      return res.status(403).json({ ok: false, error: 'Not authorized' });
    }

    const uptime = s.startedAt ? Date.now() - s.startedAt : 0;
    const uptimeSeconds = Math.floor(uptime / 1000);
    const days = Math.floor(uptimeSeconds / 86400);
    const hours = Math.floor((uptimeSeconds % 86400) / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;

    return res.json({
      ok: true,
      session: {
        sessionId: s.sessionId,
        username: undefined,
        phone: s.phone || extractWhatsAppPhoneFromSession(s),
        resumeTargetID: s.resumeTargetID || '',
        resumePhone: s.resumePhone || '',
        resumeEnabled: !!(s.resumeEnabled || s.resumeCredsHash || s.resumePhone),
        activeCredentialSlot: s.activeCredentialSlot || 'primary',
        contacts: Array.isArray(s.contacts) ? s.contacts : [],
        prefixName: s.prefixName,
        lastPrefixName: s.lastPrefixName,
        delayMs: s.delayMs,
        createdAt: s.createdAt,
        uptime: `${days} day ${hours} hour ${minutes} minute ${seconds} seconds`,
        uptimeMs: uptime,
        target: s.target,
        groupId: s.groupId,
        sessionType: s.sessionType || 'message',
        mentionType: s.mentionType || 'none',
        mentionNumbers: Array.isArray(s.mentionNumbers) ? s.mentionNumbers : [],
        mediaCount: (s.mediaFiles || []).length,
        stopped: s.stopped || false
      }
    });
  } catch (e) {
    logger.error('session details error', e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Logs API
app.post('/api/logs/:id', (req, res) => {
  try {
    const sessionId = req.params.id;
    const auth = requireApprovedAuth(req);
    if (!sessionId) return res.status(400).json({ ok: false, error: 'sessionId required' });
    if (!auth) return res.status(401).json({ ok: false, error: 'Valid approved login required' });

    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });
    if (auth.role !== 'admin' && s.username !== auth.username) return res.status(403).json({ ok: false, error: 'Not authorized' });

    const lines = (s.logs || []).map(l => `[${l.time}] ${l.msg}`);
    return res.json({ ok: true, logs: lines });
  } catch (e) {
    logger.error('api/logs error', e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Initialize admin user
initializeUsers();

// Restore sessions on startup
restoreSessionsFromDisk();

// Remove unused legacy root auth copies left by older builds.
// This is safe only when dedicated primary/ or resume/ auth directories exist.
for (const entry of (fs.existsSync(sessionsRoot) ? fs.readdirSync(sessionsRoot, { withFileTypes: true }) : [])) {
  if (entry.isDirectory()) cleanupLegacyRootAuthState(path.join(sessionsRoot, entry.name));
}
pruneUploadTempFiles();

// Remove stale multipart uploads so temporary files cannot accumulate on disk.
function pruneUploadTempFiles(maxAgeMs = 15 * 60 * 1000) {
  try {
    if (!fs.existsSync(uploadsDir)) return;
    const cutoff = Date.now() - maxAgeMs;
    for (const name of fs.readdirSync(uploadsDir)) {
      const file = path.join(uploadsDir, name);
      try {
        const st = fs.statSync(file);
        if (st.isFile() && st.mtimeMs < cutoff) fs.unlinkSync(file);
      } catch (_) {}
    }
  } catch (_) {}
}

// Global periodic prune
setInterval(() => {
  try {
    const sessionIds = Object.keys(SESSIONS);
    for (const sid of sessionIds) {
      try {
        const s = SESSIONS[sid];
        if (s && s.sessionDir) {
          const removed = pruneAuthFiles(s.sessionDir, sid);
          if (removed && removed > 0) logger.debug && logger.debug({ sid, removed }, 'Global prune removed files');
        }
      } catch (e) {}
    }
  } catch (e) {}
  try {
    for (const sid of Object.keys(SESSIONS)) {
      const s = SESSIONS[sid];
      if (s && s.sessionDir) cleanupLegacyRootAuthState(s.sessionDir);
    }
  } catch (_) {}
  pruneUploadTempFiles();
}, GLOBAL_PRUNE_INTERVAL_MS);

// Error protection - don't crash server
process.on('uncaughtException', (err) => {
  logger.error('uncaughtException: ' + (err?.message || err));
  appendSessionLog(null, '[WARN] uncaughtException (server continues): ' + (err?.message || err));
});

process.on('unhandledRejection', (err) => {
  logger.error('unhandledRejection: ' + (err?.message || err));
  appendSessionLog(null, '[WARN] unhandledRejection (server continues): ' + (err?.message || err));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(chalk.green(` [OK] Offline WhatsApp Server running on http://0.0.0.0:${PORT} `));
  logger.info('Server started on 0.0.0.0:' + PORT);
  appendSessionLog(null, `[OK] Server started on 0.0.0.0:${PORT}`);
});
