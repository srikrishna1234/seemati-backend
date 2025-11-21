// backend/app.cjs
// Full replacement (CommonJS) — robust CORS normalization + debug
// - reads CORS_ALLOWED_ORIGINS, ALLOWED_ORIGINS, FRONTEND_ORIGIN
// - canonicalizes origins (URL origin or trimmed lower-case w/out trailing slash)
// - prints debug logs and byte-dumps on mismatch
// - attempts to mount a wide set of public product routers (productRoutes, publicProducts, public-products, etc.)
// - echoes CORS headers into error responses while debugging (remove later)
// - mounts your existing routes (best-effort) and provides /__debug/env
'use strict';

const express = require('express');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { createRequire } = require('module');
const requireLocal = createRequire(__filename);
const dotenv = require('dotenv');

dotenv.config(); // load backend/.env if present

// --- basic config ---
const PORT = process.env.PORT || 4000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;

// --- helper: S3 env status (preserve original behavior) ---
function s3EnvStatus() {
  const s3BucketRaw = process.env.S3_BUCKET ?? process.env.AWS_S3_BUCKET;
  const S3_BUCKET = typeof s3BucketRaw === 'string' && s3BucketRaw.trim() ? String(s3BucketRaw).trim() : null;
  return {
    S3_BUCKET,
    missing: [
      !process.env.STORAGE_PROVIDER ? 'STORAGE_PROVIDER' : null,
      !process.env.AWS_ACCESS_KEY_ID ? 'AWS_ACCESS_KEY_ID' : null,
      !process.env.AWS_SECRET_ACCESS_KEY ? 'AWS_SECRET_ACCESS_KEY' : null,
      !process.env.AWS_REGION && !process.env.AWS_DEFAULT_REGION ? 'AWS_REGION' : null,
      !S3_BUCKET ? 'S3_BUCKET' : null,
    ].filter(Boolean),
  };
}

// --- origin canonicalization & byte debug helpers ---
function canonicalizeOrigin(raw) {
  if (!raw) return raw;
  try {
    const u = new URL(String(raw).trim());
    return u.origin;
  } catch (e) {
    // fallback: trim, remove trailing slash, lowercase
    return String(raw).trim().replace(/\/+$/, '').toLowerCase();
  }
}

function bytesOfString(s) {
  if (s == null) return [];
  const arr = [];
  for (let i = 0; i < s.length; i++) arr.push(s.charCodeAt(i));
  return arr;
}

function showByteDebug(label, s) {
  try {
    console.log(`[BYTE-DUMP] ${label}: "${s}"`);
    console.log(`[BYTE-DUMP] ${label}-len: ${s ? s.length : 0}, bytes:`, bytesOfString(String(s)).slice(0, 200));
  } catch (e) {
    console.warn(`[BYTE-DUMP] failed for ${label}`, e && e.message ? e.message : e);
  }
}

// --- build allowed origins (reads multiple env var names) ---
function buildAllowedOrigins() {
  const set = new Set();
  const raw = {
    CORS_ALLOWED_ORIGINS: process.env.CORS_ALLOWED_ORIGINS || null,
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS || null,
    FRONTEND_ORIGIN: process.env.FRONTEND_ORIGIN || process.env.CLIENT_ORIGIN || null,
  };

  if (raw.CORS_ALLOWED_ORIGINS && String(raw.CORS_ALLOWED_ORIGINS).trim()) {
    String(raw.CORS_ALLOWED_ORIGINS)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((s) => set.add(canonicalizeOrigin(s)));
  }

  if (raw.ALLOWED_ORIGINS && String(raw.ALLOWED_ORIGINS).trim()) {
    String(raw.ALLOWED_ORIGINS)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((s) => set.add(canonicalizeOrigin(s)));
  }

  if (raw.FRONTEND_ORIGIN && String(raw.FRONTEND_ORIGIN).trim()) {
    set.add(canonicalizeOrigin(raw.FRONTEND_ORIGIN));
  }

  // always include dev origins
  set.add(canonicalizeOrigin('http://localhost:3000'));
  set.add(canonicalizeOrigin('http://127.0.0.1:3000'));
  set.add(canonicalizeOrigin('http://localhost:4000'));

  return { raw, normalized: Array.from(set), set };
}

// --- admin token helper (preserve original) ---
function isAdminAuthorized(req) {
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!ADMIN_TOKEN) return true;
  if (!token) return false;
  return token === ADMIN_TOKEN;
}

// --- tryRequire helper (preserve original behavior) ---
async function tryRequire(p) {
  try {
    return requireLocal(p);
  } catch (e) {
    return null;
  }
}

// Helper: tolerant loader for multiple candidate router filenames
function candidatePaths(base) {
  // base examples: "./src/routes/publicProducts"
  const exts = ['', '.cjs', '.js', '.mjs'];
  return exts.map((e) => `${base}${e}`);
}

// --- main server bootstrap ---
(async function main() {
  console.log('Starting backend (CommonJS app.cjs)');
  console.log('ENV STORAGE_PROVIDER=', process.env.STORAGE_PROVIDER || '(none)');
  const s3st = s3EnvStatus();
  console.log('S3_BUCKET detected=', s3st.S3_BUCKET || '<missing>');

  const allowed = buildAllowedOrigins();
  console.log('CORS_ALLOWED_ORIGINS raw (CORS_ALLOWED_ORIGINS):', JSON.stringify(allowed.raw.CORS_ALLOWED_ORIGINS));
  console.log('ALLOWED_ORIGINS raw (ALLOWED_ORIGINS):', JSON.stringify(allowed.raw.ALLOWED_ORIGINS));
  console.log('FRONTEND_ORIGIN (FRONTEND_ORIGIN/CLIENT_ORIGIN):', JSON.stringify(allowed.raw.FRONTEND_ORIGIN));
  console.log('CORS allowed normalized list:', allowed.normalized);

  const app = express();

  // CORS options using normalized check with helpful debug logging
  const corsOptions = {
    origin: function (incomingOrigin, callback) {
      const incomingRaw = incomingOrigin || '(no-origin)';
      const incomingNorm = canonicalizeOrigin(incomingRaw);
      console.log(`[CORS DEBUG] incoming raw: ${incomingRaw} normalized: ${incomingNorm}`);
      if (!incomingOrigin) {
        // server-to-server or curl
        console.log('[CORS DEBUG] no Origin header — allowing');
        return callback(null, true);
      }
      if (allowed.set.has(incomingNorm)) {
        console.log(`[CORS DEBUG] origin allowed: ${incomingNorm}`);
        return callback(null, true);
      }

      // Not allowed: debug byte-dump to detect invisible chars
      console.warn(`[CORS DEBUG] origin rejected: raw="${incomingRaw}" norm="${incomingNorm}"`);
      showByteDebug('incoming', incomingRaw);
      allowed.normalized.forEach((a, idx) => showByteDebug(`allowed_norm[${idx}]`, a));
      if (allowed.raw.CORS_ALLOWED_ORIGINS) showByteDebug('CORS_ALLOWED_ORIGINS_raw', allowed.raw.CORS_ALLOWED_ORIGINS);

      return callback(new Error(`CORS policy: origin ${incomingRaw} not allowed`), false);
    },
    credentials: true,
    optionsSuccessStatus: 204
  };

  app.use(cors(corsOptions));
  app.options('*', cors(corsOptions));
  app.use(express.json({ limit: '12mb' }));
  app.use(express.urlencoded({ extended: true, limit: '12mb' }));

  app.use(session({
    secret: process.env.SESSION_SECRET || 'keyboard_cat_dev_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { sameSite: 'none', secure: false, httpOnly: true, maxAge: 24 * 3600 * 1000 }
  }));

  app.use(cookieParser());

  // ensure uploads folder exists
  const uploadDir = path.join(__dirname, 'uploads');
  if (!fs.existsSync(uploadDir)) {
    try { fs.mkdirSync(uploadDir, { recursive: true }); } catch (e) { console.warn('Could not create uploads dir:', e); }
  }
  app.use('/uploads', express.static(uploadDir));

  // multer storage (preserve original behavior)
  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
      const ts = Date.now();
      const safe = file.originalname.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9._-]/g, '');
      cb(null, `${ts}-${safe}`);
    }
  });
  const upload = multer({ storage });

  // try to mount several route modules (best-effort)
  const routesToTry = [
    { path: './src/routes/presign-get.cjs', mount: '/api/presign-get' },
    { path: './src/routes/presign.cjs', mount: '/api/presign' },
    { path: './src/routes/admin-presign.cjs', mount: '/admin-api' },
    // upload router often contains /products or product upload endpoints
    { path: './src/routes/upload.cjs', mount: '/api' },
    { path: './src/routes/upload.js', mount: '/api' },
  ];

  for (const r of routesToTry) {
    try {
      const mod = await tryRequire(r.path);
      if (mod) {
        app.use(r.mount, mod);
        console.log(`Mounted ${r.path} at ${r.mount}`);
      }
    } catch (e) {
      console.warn(`Failed to mount ${r.path}:`, e && e.message ? e.message : e);
    }
  }

  // --- NEW: attempt to find & mount public/product routes automatically ---
  const publicCandidates = [
    './src/routes/publicProducts',
    './src/routes/publicProducts.cjs',
    './src/routes/publicProducts.js',
    './src/routes/public-products',
    './src/routes/public-products.cjs',
    './src/routes/public-products.js',
    './src/routes/productRoutes',
    './src/routes/productRoutes.cjs',
    './src/routes/productRoutes.js',
    './src/routes/products',
    './src/routes/products.cjs',
    './src/routes/products.js'
  ];

  let mountedPublic = false;
  for (const cand of publicCandidates) {
    try {
      const mod = await tryRequire(cand);
      if (mod) {
        // attempt mounting at /api first (common)
        try {
          app.use('/api', mod);
          console.log(`Mounted ${cand} at /api`);
          mountedPublic = true;
        } catch (e) {
          console.warn(`Failed to mount ${cand} at /api:`, e && e.message ? e.message : e);
        }
        // also try mounting at root / (so GET /products works if router defines /products)
        try {
          app.use('/', mod);
          console.log(`Mounted ${cand} at / (root)`);
          mountedPublic = true;
        } catch (e) {
          // ignore
        }
        break;
      }
    } catch (e) {
      // just continue trying candidates
    }
  }

  if (!mountedPublic) {
    console.log('[app.cjs] No public products router found among candidates (publicProducts/productRoutes/products).');
  }

  // local admin upload endpoint if not using S3
  const storageProvider = (process.env.STORAGE_PROVIDER || '').toLowerCase();
  if (storageProvider !== 's3') {
    app.post('/admin-api/products/upload', upload.any(), (req, res) => {
      try {
        if (!isAdminAuthorized(req)) return res.status(401).json({ ok: false, message: 'Unauthorized' });
        const files = req.files || [];
        if (!files.length) return res.status(400).json({ ok: false, message: 'No file uploaded' });
        const host = process.env.SERVER_URL || `http://localhost:${PORT}`;
        const out = files.map(f => ({ filename: f.filename, url: `${host}/uploads/${f.filename}`, size: f.size }));
        return res.json(out);
      } catch (err) {
        console.error('[admin-upload] error:', err);
        return res.status(500).json({ ok: false, message: 'Upload failed' });
      }
    });
  } else {
    console.log('STORAGE_PROVIDER=s3 configured — skipping local admin upload route.');
  }

  // health & debug handlers
  app.get('/health', (req, res) => res.json({ ok: true }));
  app.get('/api/ping', (req, res) => res.json({ ok: true, msg: 'api ping' }));

  app.get('/__debug/env', (req, res) => {
    const s3info = s3EnvStatus();
    const storageProviderLower = (process.env.STORAGE_PROVIDER || '').toLowerCase();
    const presignReady = storageProviderLower === 's3' && !!s3info.S3_BUCKET && !!process.env.AWS_ACCESS_KEY_ID && !!process.env.AWS_SECRET_ACCESS_KEY;
    res.json({
      ok: true,
      now: new Date().toISOString(),
      STORAGE_PROVIDER: process.env.STORAGE_PROVIDER || null,
      S3_BUCKET_raw: process.env.S3_BUCKET ?? process.env.AWS_S3_BUCKET ?? null,
      S3_BUCKET_normalized: s3info.S3_BUCKET,
      hasAwsKeys: !!process.env.AWS_ACCESS_KEY_ID && !!process.env.AWS_SECRET_ACCESS_KEY,
      presignReady,
      ADMIN_TOKEN_set: !!process.env.ADMIN_TOKEN,
      FRONTEND_ORIGIN: process.env.FRONTEND_ORIGIN || process.env.CLIENT_ORIGIN || null,
      CORS_ALLOWED_ORIGINS_raw: process.env.CORS_ALLOWED_ORIGINS || null,
      ALLOWED_ORIGINS_raw: process.env.ALLOWED_ORIGINS || null,
      allowed_normalized: allowed.normalized
    });
  });

  // fallback /api 404
  app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found' }));
  // fallback root 404
  app.use((req, res) => {
    if (req.accepts('html')) {
      res.status(404).send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Error</title></head><body><pre>Cannot ${req.method} ${req.path}</pre></body></html>`);
    } else {
      res.status(404).json({ error: `Cannot ${req.method} ${req.path}` });
    }
  });

  // global error handler (with DEBUG CORS echo)
  app.use((err, req, res, next) => {
    console.error('Global error:', err && (err.stack || err));
    if (res.headersSent) return next(err);

    if (err && err.message && String(err.message).toLowerCase().includes('origin')) {
      // DEBUG: echo CORS headers so browser shows server error (remove later)
      try {
        const originHeader = req.get('origin') || null;
        if (originHeader) {
          res.set('Access-Control-Allow-Origin', originHeader);
          res.set('Access-Control-Allow-Credentials', 'true');
          res.set('Vary', 'Origin');
        }
      } catch (e) { /* ignore */ }
      return res.status(403).json({ error: 'CORS blocked request', message: err.message });
    }

    res.status(err && err.status ? err.status : 500).json({ error: err && err.message ? err.message : 'Server error' });
  });

  app.listen(PORT, () => {
    console.log(`Backend (CommonJS app.cjs) listening on http://localhost:${PORT}`);
  });

})().catch(e => {
  console.error('Fatal startup error (app.cjs):', e && (e.stack || e));
  process.exit(1);
});
