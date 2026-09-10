require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { mongoSanitizeMiddleware } = require('../lib/security');
const authRoutes = require('../routes/auth');

const app = express();

// Enable reverse proxy support for accurate IP rate limiting on Vercel / Cloudflare
app.set('trust proxy', 1);

// ── 1. HTTP Security Headers (Helmet) ──────────────────────────────────────
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    contentSecurityPolicy: false, // Handled by frontend host
  })
);

// ── 2. CORS Configuration ──────────────────────────────────────────────────
const allowedOrigins = [
  'https://loccomirror-web.vercel.app',
  'https://raghavkainse.github.io',
  'https://app.mirrorflow',
  'http://localhost:5173',
  'http://localhost:3000',
  'http://localhost:5000',
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl, WebView2 IPC) or allowed origins
      if (!origin || allowedOrigins.includes(origin) || origin.endsWith('.vercel.app') || origin.endsWith('.github.io')) {
        return callback(null, true);
      }
      return callback(null, true); // Allow all for seamless multi-client access while sending standard headers
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    maxAge: 86400, // 24 hours preflight cache
  })
);

// ── 3. Payload Size Limitation (Prevent Denial of Service / Buffer Bloat) ───
app.use(express.json({ limit: '15kb' }));
app.use(express.urlencoded({ extended: true, limit: '15kb' }));

// ── 4. NoSQL Query & Input Sanitization ─────────────────────────────────────
app.use(mongoSanitizeMiddleware);

// ── 5. Rate Limiting (DDoS & Brute Force Attack Mitigation) ─────────────────
// Global API rate limit: 120 requests per 10 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP address. Please try again after 10 minutes.',
  },
});

app.use('/api/', globalLimiter);

// Strict Rate limit for Authentication (Login / Signup): 15 attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many authentication attempts. Please wait 15 minutes before trying again.',
  },
});

// ── 6. Routes & Endpoints ──────────────────────────────────────────────────
// Root Health / Info endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    service: 'loccoMirror Cloud Authentication API',
    status: 'online',
    security: {
      rateLimiting: 'active',
      encryption: 'bcrypt + jwt',
      nosqlProtection: 'enabled',
      headers: 'helmet-secured',
    },
    version: '1.1.0',
    documentation: 'https://github.com/RaghavKainse/loccomirror-api',
  });
});

// Mount Auth routes with strict rate limiting
app.use('/api/auth', authLimiter, authRoutes);

// ── 6.1 Update Check Endpoint ──────────────────────────────────────────────
const https = require('https');

let cachedRelease = null;
let lastReleaseFetchTime = 0;

function fetchLatestGitHubRelease() {
  return new Promise((resolve) => {
    const options = {
      hostname: 'api.github.com',
      path: '/repos/RaghavKainse/loccomirror/releases/latest',
      method: 'GET',
      headers: { 'User-Agent': 'LoccoMirror-UpdateServer/1.0' },
      timeout: 4000,
    };

    const req = https.request(options, (res) => {
      if (res.statusCode !== 200) {
        return resolve(null);
      }
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          const tag = data.tag_name ? data.tag_name.replace(/^[vV]/, '') : '1.0.0';
          let dl = '';
          if (data.assets && Array.isArray(data.assets) && data.assets.length > 0) {
            const exeAsset = data.assets.find(a => a.name && a.name.toLowerCase().endsWith('.exe')) || data.assets[0];
            dl = exeAsset.browser_download_url;
          }
          if (!dl) {
            dl = `https://github.com/RaghavKainse/loccomirror/releases/download/v${tag}/LoccoMirror_Setup_v${tag}.exe`;
          }
          resolve({
            latest_version: tag,
            min_version: '1.0.0',
            download_url: dl,
            release_notes: data.body || '• Real-time Direct3D 11 NV12 Hardware Mirroring\n• OBS Studio Native Capture Fix\n• Automatic Software Update System',
            mandatory: false,
          });
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

app.get('/api/update/check', async (req, res) => {
  const now = Date.now();
  if (!cachedRelease || (now - lastReleaseFetchTime > 5 * 60 * 1000)) {
    const liveRelease = await fetchLatestGitHubRelease();
    if (liveRelease) {
      cachedRelease = liveRelease;
      lastReleaseFetchTime = now;
    }
  }

  const payload = cachedRelease || {
    latest_version: '1.0.0',
    min_version: '1.0.0',
    download_url: 'https://github.com/RaghavKainse/loccomirror/releases/download/v1.0.0/LoccoMirror_Setup_v1.0.0.exe',
    sha256: '',
    release_notes: '• Real-time Direct3D 11 NV12 Hardware Mirroring\n• OBS Studio Native Capture Fix\n• Automatic Software Update System',
    mandatory: false,
  };

  res.status(200).json(payload);
});

// ── 7. 404 Route Handler ────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Endpoint ${req.method} ${req.originalUrl} not found.`,
  });
});

// ── 8. Secure Global Error Handler (Suppresses internal stack traces) ───────
app.use((err, req, res, next) => {
  console.error('[API Error]:', err.message);
  
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      success: false,
      message: 'Payload size exceeds the allowable limit (15kb).',
    });
  }

  const isDev = process.env.NODE_ENV === 'development';
  res.status(err.status || 500).json({
    success: false,
    message: isDev ? err.message : 'An unexpected server error occurred. Please try again later.',
  });
});

// For local development
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`[loccoMirror Backend] Secure server running on http://localhost:${PORT}`);
  });
}

// Export for Vercel Serverless
module.exports = app;
