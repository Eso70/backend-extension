import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import express from 'express';
import rateLimit from 'express-rate-limit';
import { OAuth2Client } from 'google-auth-library';
import helmet from 'helmet';
import pg from 'pg';
import { renderStatCard, renderStatCardGrid } from './admin-ui-components.js';

dotenv.config();

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3033);
const host = process.env.HOST || '127.0.0.1';
const advertiserIdPattern = /^\d{5,32}$/;
const maxAdvertiserAccountsPerUser = 25;

for (const name of [
  'DB_HOST',
  'DB_PORT',
  'DB_NAME',
  'DB_USER',
  'DB_PASSWORD',
  'ADMIN_CSRF_SECRET',
  'ADMIN_SESSION_SECRET',
  'ADMIN_PATH',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_REDIRECT_URI',
  'GOOGLE_USER_REDIRECT_URI',
  'ADMIN_GOOGLE_EMAILS'
]) {
  if (!process.env[name]) throw new Error(`Missing required environment variable: ${name}`);
}

const databasePort = Number(process.env.DB_PORT);
const databasePoolSize = Number(process.env.DB_POOL_SIZE || 10);
const adminBasePath = String(process.env.ADMIN_PATH || '').trim().replace(/\/$/, '');
const adminSessionHours = Number(process.env.ADMIN_SESSION_HOURS || 8);
const userSessionDays = Number(process.env.USER_SESSION_DAYS || 30);
const googleRedirectUri = new URL(process.env.GOOGLE_REDIRECT_URI);
const googleUserRedirectUri = new URL(process.env.GOOGLE_USER_REDIRECT_URI);
const adminGoogleEmails = new Set(
  String(process.env.ADMIN_GOOGLE_EMAILS)
    .split(',')
    .map(value => value.trim().toLowerCase())
    .filter(Boolean)
);
const googleOAuthClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  googleRedirectUri.toString()
);
const googleUserOAuthClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  googleUserRedirectUri.toString()
);
if (!Number.isInteger(databasePort) || databasePort < 1 || databasePort > 65535) {
  throw new Error('DB_PORT must be a valid TCP port.');
}
if (!Number.isInteger(databasePoolSize) || databasePoolSize < 1 || databasePoolSize > 100) {
  throw new Error('DB_POOL_SIZE must be an integer from 1 to 100.');
}
if (!/^\/[A-Za-z0-9_-]{16,100}$/.test(adminBasePath)) {
  throw new Error('ADMIN_PATH must start with / and contain 16 to 100 letters, numbers, dashes, or underscores.');
}
if (!Number.isFinite(adminSessionHours) || adminSessionHours < 1 || adminSessionHours > 24) {
  throw new Error('ADMIN_SESSION_HOURS must be between 1 and 24.');
}
if (!Number.isInteger(userSessionDays) || userSessionDays < 1 || userSessionDays > 365) {
  throw new Error('USER_SESSION_DAYS must be an integer from 1 to 365.');
}
if (googleRedirectUri.pathname !== `${adminBasePath}/google/callback`) {
  throw new Error('GOOGLE_REDIRECT_URI must end with ADMIN_PATH/google/callback.');
}
if (isProduction && googleRedirectUri.protocol !== 'https:') {
  throw new Error('GOOGLE_REDIRECT_URI must use HTTPS in production.');
}
if (googleUserRedirectUri.pathname !== '/api/v1/auth/google/callback') {
  throw new Error('GOOGLE_USER_REDIRECT_URI must end with /api/v1/auth/google/callback.');
}
if (isProduction && googleUserRedirectUri.protocol !== 'https:') {
  throw new Error('GOOGLE_USER_REDIRECT_URI must use HTTPS in production.');
}
if (adminGoogleEmails.size === 0 || [...adminGoogleEmails].some(email => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
  throw new Error('ADMIN_GOOGLE_EMAILS must contain one or more valid comma-separated email addresses.');
}

const allowedExtensionOrigins = new Set(
  String(process.env.ALLOWED_EXTENSION_ORIGINS || '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean)
);

if (isProduction && allowedExtensionOrigins.size === 0) {
  throw new Error('ALLOWED_EXTENSION_ORIGINS is required in production.');
}

const pool = new Pool({
  host: process.env.DB_HOST,
  port: databasePort,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: databasePoolSize,
  ssl: String(process.env.DB_SSL).toLowerCase() === 'true'
    ? { rejectUnauthorized: true }
    : false
});

await pool.query(`
  CREATE TABLE IF NOT EXISTS allowed_ad_accounts (
    id BIGSERIAL PRIMARY KEY,
    advertiser_id VARCHAR(32) NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    note VARCHAR(200) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS extension_users (
    id BIGSERIAL PRIMARY KEY,
    google_subject VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(320) NOT NULL,
    display_name VARCHAR(200) NOT NULL DEFAULT '',
    picture_url TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE UNIQUE INDEX IF NOT EXISTS extension_users_email_lower_idx
    ON extension_users (LOWER(email));

  CREATE TABLE IF NOT EXISTS extension_oauth_states (
    state_hash CHAR(64) PRIMARY KEY,
    nonce VARCHAR(128) NOT NULL,
    extension_redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
  );

  CREATE TABLE IF NOT EXISTS extension_login_codes (
    code_hash CHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES extension_users(id) ON DELETE CASCADE,
    extension_redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
  );

  CREATE TABLE IF NOT EXISTS extension_sessions (
    token_hash CHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES extension_users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS extension_user_ad_accounts (
    user_id BIGINT NOT NULL REFERENCES extension_users(id) ON DELETE CASCADE,
    advertiser_id VARCHAR(32) NOT NULL,
    last_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, advertiser_id)
  );

  CREATE TABLE IF NOT EXISTS extension_user_account_assignments (
    user_id BIGINT NOT NULL REFERENCES extension_users(id) ON DELETE CASCADE,
    advertiser_id VARCHAR(32) NOT NULL REFERENCES allowed_ad_accounts(advertiser_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, advertiser_id)
  );

  DO $$
  BEGIN
    IF EXISTS (
      SELECT 1
      FROM pg_constraint
      WHERE conname = 'extension_user_account_assignments_advertiser_id_fkey'
        AND confupdtype <> 'c'
    ) THEN
      ALTER TABLE extension_user_account_assignments
        DROP CONSTRAINT extension_user_account_assignments_advertiser_id_fkey;
      ALTER TABLE extension_user_account_assignments
        ADD CONSTRAINT extension_user_account_assignments_advertiser_id_fkey
        FOREIGN KEY (advertiser_id)
        REFERENCES allowed_ad_accounts(advertiser_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE;
    END IF;
  END;
  $$;

  CREATE OR REPLACE FUNCTION enforce_extension_user_account_limit()
  RETURNS TRIGGER AS $$
  BEGIN
    IF (
      SELECT COUNT(*)
      FROM extension_user_account_assignments
      WHERE user_id = NEW.user_id
    ) >= ${maxAdvertiserAccountsPerUser} THEN
      RAISE EXCEPTION 'Each extension user can have at most ${maxAdvertiserAccountsPerUser} advertiser accounts.'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END;
  $$ LANGUAGE plpgsql;

  DROP TRIGGER IF EXISTS extension_user_account_limit_trigger
    ON extension_user_account_assignments;
  CREATE TRIGGER extension_user_account_limit_trigger
    BEFORE INSERT ON extension_user_account_assignments
    FOR EACH ROW
    EXECUTE FUNCTION enforce_extension_user_account_limit();
`);

// Enforce the current absolute session lifetime for records created by older
// deployments, then remove anything that is already expired.
await pool.query(
  `UPDATE extension_sessions
      SET expires_at = created_at + ($1 * INTERVAL '1 day')
    WHERE expires_at > created_at + ($1 * INTERVAL '1 day')`,
  [userSessionDays]
);
await pool.query('DELETE FROM extension_sessions WHERE expires_at <= NOW()');

const app = express();
app.disable('x-powered-by');
if (isProduction) app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      imgSrc: ["'self'", 'https:', 'data:'],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"]
    }
  },
  referrerPolicy: { policy: 'no-referrer' }
}));

app.use(express.json({ limit: '4kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '8kb' }));

app.get('/about', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});
app.get('/privacy', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});
app.get('/terms', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});
app.get('/legal/legal.css', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'legal.css')));
app.get('/legal/kurdish-font.ttf', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'kurdish-font.ttf')));
app.get('/legal/logo.png', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.png')));

const authorizationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { allowed: false, message: 'Too many authorization checks. Try again later.' }
});

const userLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Try again later.' }
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: 'Too many login attempts. Try again in 15 minutes.'
});

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function parseCookies(header = '') {
  return Object.fromEntries(
    header.split(';').map(part => part.trim()).filter(Boolean).map(part => {
      const separator = part.indexOf('=');
      return separator < 0
        ? [part, '']
        : [part.slice(0, separator), decodeURIComponent(part.slice(separator + 1))];
    })
  );
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function extensionIdFromOrigin(origin) {
  const match = String(origin || '').match(/^chrome-extension:\/\/([a-p]{32})$/);
  return match?.[1] || '';
}

function isAllowedExtensionRedirect(value) {
  try {
    const redirect = new URL(String(value || ''));
    const match = redirect.hostname.match(/^([a-p]{32})\.chromiumapp\.org$/);
    if (redirect.protocol !== 'https:' || !match || redirect.pathname !== '/google') return false;
    if (allowedExtensionOrigins.size === 0 && !isProduction) return true;
    return allowedExtensionOrigins.has(`chrome-extension://${match[1]}`);
  } catch {
    return false;
  }
}

function appendQuery(url, params) {
  const target = new URL(url);
  for (const [key, value] of Object.entries(params)) target.searchParams.set(key, value);
  return target.toString();
}

async function getExtensionUserFromRequest(req) {
  const match = String(req.headers.authorization || '').match(/^Bearer\s+([A-Za-z0-9_-]{32,256})$/);
  if (!match) return null;
  const result = await pool.query(
    `SELECT u.id, u.email, u.display_name, u.picture_url
       FROM extension_sessions s
       JOIN extension_users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > NOW() AND u.enabled = TRUE
      LIMIT 1`,
    [sha256(match[1])]
  );
  if (!result.rows[0]) return null;
  await Promise.all([
    pool.query(
      `UPDATE extension_sessions
          SET last_seen_at = NOW()
        WHERE token_hash = $1`,
      [sha256(match[1])]
    ),
    pool.query('UPDATE extension_users SET last_seen_at = NOW() WHERE id = $1', [result.rows[0].id])
  ]);
  return result.rows[0];
}

async function requireExtensionUser(req, res, next) {
  try {
    const user = await getExtensionUserFromRequest(req);
    if (!user) {
      res.status(401).json({ error: 'Sign in with Google to use the extension.' });
      return;
    }
    req.extensionUser = user;
    next();
  } catch (error) {
    next(error);
  }
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function safeHttpsImageUrl(value) {
  try {
    const url = new URL(String(value || ''));
    return url.protocol === 'https:' ? escapeHtml(url.toString()) : '';
  } catch {
    return '';
  }
}

const dashboardIconPaths = {
  menu: '<path d="M4 6h16"></path><path d="M4 12h16"></path><path d="M4 18h16"></path>',
  refresh: '<path d="M20 11a8.1 8.1 0 0 0-15.5-2M4 4v5h5"></path><path d="M4 13a8.1 8.1 0 0 0 15.5 2M20 20v-5h-5"></path>',
  moon: '<path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401"></path>',
  sun: '<circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M22 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path>',
  hash: '<line x1="4" x2="20" y1="9" y2="9"></line><line x1="4" x2="20" y1="15" y2="15"></line><line x1="10" x2="8" y1="3" y2="21"></line><line x1="16" x2="14" y1="3" y2="21"></line>',
  shield: '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3z"></path><path d="m9 12 2 2 4-4"></path>',
  ban: '<circle cx="12" cy="12" r="10"></circle><path d="m4.9 4.9 14.2 14.2"></path>',
  layout: '<rect width="7" height="9" x="3" y="3" rx="1"></rect><rect width="7" height="5" x="14" y="3" rx="1"></rect><rect width="7" height="9" x="14" y="12" rx="1"></rect><rect width="7" height="5" x="3" y="16" rx="1"></rect>',
  search: '<circle cx="11" cy="11" r="8"></circle><path d="m21 21-4.3-4.3"></path>',
  chevronDown: '<path d="m6 9 6 6 6-6"></path>',
  plus: '<path d="M5 12h14"></path><path d="M12 5v14"></path>',
  power: '<path d="M12 2v10"></path><path d="M18.4 6.6a9 9 0 1 1-12.77.04"></path>',
  edit: '<path d="M12 20h9"></path><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"></path>',
  trash: '<path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"></path><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" x2="10" y1="11" y2="17"></line><line x1="14" x2="14" y1="11" y2="17"></line>',
  logout: '<path d="M10 17l5-5-5-5"></path><path d="M15 12H3"></path><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path>',
  chevron: '<path d="m9 18 6-6-6-6"></path>',
  close: '<path d="M18 6 6 18"></path><path d="m6 6 12 12"></path>'
};

function dashboardIcon(name, className = '') {
  return `<svg class="lucide ${escapeHtml(className)}" viewBox="0 0 24 24" aria-hidden="true">${dashboardIconPaths[name] || ''}</svg>`;
}

function formatDashboardDate(value) {
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  }).format(new Date(value));
}

function createAdminSessionToken(email, pictureUrl = '') {
  const payload = Buffer.from(JSON.stringify({
    sub: email,
    picture: String(pictureUrl || '').slice(0, 2000),
    exp: Date.now() + adminSessionHours * 60 * 60 * 1000
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', process.env.ADMIN_SESSION_SECRET)
    .update(`admin-session:${payload}`).digest('base64url');
  return `${payload}.${signature}`;
}

function readAdminSessionToken(token) {
  try {
    const [payload, signature] = String(token || '').split('.');
    if (!payload || !signature) return null;
    const expected = crypto.createHmac('sha256', process.env.ADMIN_SESSION_SECRET)
      .update(`admin-session:${payload}`).digest('base64url');
    if (!safeEqual(signature, expected)) return null;
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return adminGoogleEmails.has(String(session.sub || '').toLowerCase())
      && Number.isFinite(session.exp)
      && session.exp > Date.now()
      ? session
      : null;
  } catch {
    return null;
  }
}

function hasAdminSession(req) {
  return Boolean(readAdminSessionToken(parseCookies(req.headers.cookie).krd_admin_session));
}

function requireAdminSession(req, res, next) {
  const session = readAdminSessionToken(parseCookies(req.headers.cookie).krd_admin_session);
  if (!session) {
    res.redirect(303, `${adminBasePath}/login`);
    return;
  }
  req.adminSession = session;
  next();
}

function setCsrfCookie(res, token) {
  res.cookie('admin_csrf', token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: adminBasePath,
    maxAge: adminSessionHours * 60 * 60 * 1000
  });
}

function setOAuthCookie(res, name, value) {
  res.cookie(name, value, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: adminBasePath,
    maxAge: 10 * 60 * 1000
  });
}

function clearOAuthCookies(res) {
  res.clearCookie('admin_oauth_state', { path: adminBasePath });
  res.clearCookie('admin_oauth_nonce', { path: adminBasePath });
}

function createCsrfToken() {
  const nonce = crypto.randomBytes(32).toString('base64url');
  const signature = crypto.createHmac('sha256', process.env.ADMIN_CSRF_SECRET)
    .update(nonce).digest('base64url');
  return `${nonce}.${signature}`;
}

function isValidCsrfToken(token) {
  const [nonce, signature] = String(token || '').split('.');
  if (!nonce || !signature) return false;
  const expected = crypto.createHmac('sha256', process.env.ADMIN_CSRF_SECRET)
    .update(nonce).digest('base64url');
  return safeEqual(signature, expected);
}

function requireCsrf(req, res, next) {
  const cookieToken = parseCookies(req.headers.cookie).admin_csrf;
  const bodyToken = req.body?._csrf;
  if (!cookieToken || !bodyToken || !safeEqual(cookieToken, bodyToken) || !isValidCsrfToken(bodyToken)) {
    res.status(403).type('text').send('تۆکنی فۆڕمەکە نادروستە یان کاتی بەسەرچووە. پەڕەی بەڕێوەبەر نوێ بکەرەوە.');
    return;
  }
  next();
}

function requireAllowedExtensionOrigin(req, res, next) {
  const origin = String(req.headers.origin || '');
  if (allowedExtensionOrigins.size > 0 && !allowedExtensionOrigins.has(origin)) {
    res.status(403).json({ allowed: false, message: 'Extension origin is not allowed.' });
    return;
  }

  if (origin && (allowedExtensionOrigins.size === 0 || allowedExtensionOrigins.has(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
}

function renderLoginPage(errorMessage = '') {
  return `<!doctype html>
  <html lang="ckb" dir="ltr">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>بەڕێوەبەر | Sponsor.krd Extension</title>
      <link rel="icon" type="image/png" href="${adminBasePath}/logo.png">
      <link rel="stylesheet" href="${adminBasePath}/admin.css">
      <script src="${adminBasePath}/admin.js" defer></script>
    </head>
    <body class="login-page">
      <main class="login-shell">
        <button class="floating-control back-control" type="button" data-back aria-label="گەڕانەوە">
          <svg class="lucide lucide-arrow-left" viewBox="0 0 24 24" aria-hidden="true"><path d="m12 19-7-7 7-7"></path><path d="M19 12H5"></path></svg>
        </button>
        <button class="floating-control theme-control" type="button" data-theme-toggle aria-label="گۆڕینی ڕووکار">
          <svg class="lucide lucide-moon theme-icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401"></path></svg>
          <svg class="lucide lucide-sun theme-icon-sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>
        </button>
        <section class="login-side" aria-labelledby="login-title">
          <div class="login-center">
            <section class="login-card">
              <div class="login-copy" dir="ltr">
                <h1 id="login-title">چوونەژوورەوەی بەڕێوەبەر</h1>
                <p>بە هەژماری Google بڕۆ ژوورەوە</p>
              </div>
              ${errorMessage ? `<div class="form-alert" role="alert">${escapeHtml(errorMessage)}</div>` : ''}
              <a class="google-login-button" href="${adminBasePath}/google">
                <svg class="google-mark" viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M21.6 12.23c0-.71-.06-1.4-.18-2.07H12v3.92h5.38a4.6 4.6 0 0 1-2 3.02v2.54h3.24c1.9-1.75 2.98-4.33 2.98-7.41Z"></path><path fill="#34A853" d="M12 22c2.7 0 4.97-.9 6.62-2.42l-3.24-2.53c-.9.6-2.05.96-3.38.96-2.61 0-4.82-1.76-5.61-4.13H3.04v2.61A10 10 0 0 0 12 22Z"></path><path fill="#FBBC05" d="M6.39 13.88A6.02 6.02 0 0 1 6.08 12c0-.65.11-1.29.31-1.88V7.51H3.04A10 10 0 0 0 2 12c0 1.61.39 3.14 1.04 4.49l3.35-2.61Z"></path><path fill="#EA4335" d="M12 5.99c1.47 0 2.79.5 3.83 1.5l2.87-2.87A9.63 9.63 0 0 0 12 2a10 10 0 0 0-8.96 5.51l3.35 2.61C7.18 7.75 9.39 5.99 12 5.99Z"></path></svg>
                <span>بە Google بەردەوام بە</span>
              </a>
            </section>
          </div>
        </section>
        <aside class="login-visual" aria-hidden="true">
          <div class="visual-orb visual-orb-one"></div>
          <div class="visual-orb visual-orb-two"></div>
          <div class="visual-content">
            <span class="visual-mark"><img src="${adminBasePath}/logo.png" alt=""></span>
            <p>Sponsor.krd Extension</p>
            <h2 dir="ltr">پانێڵی بەڕێوەبردن</h2>
            <span class="visual-subtitle" dir="ltr">بڕۆ ژوورەوە بۆ بەڕێوەبردنی هەژمارەکان</span>
            <span class="visual-line"></span>
          </div>
        </aside>
      </main>
    </body>
  </html>`;
}

function renderAdminPage(accounts, users, csrfToken, administratorEmail, administratorPictureUrl = '') {
  const assignedAccountCount = users.reduce((total, user) => total + (Array.isArray(user.ad_accounts) ? user.ad_accounts.length : 0), 0);
  const assignedUserCount = users.filter(user => Array.isArray(user.ad_accounts) && user.ad_accounts.length > 0).length;
  const recentUserCount = users.filter(user => Date.now() - new Date(user.last_seen_at).getTime() <= 7 * 24 * 60 * 60 * 1000).length;
  const unassignedUserCount = users.length - assignedUserCount;
  const enabledAccountCount = accounts.filter(account => account.enabled).length;
  const administratorInitial = escapeHtml(String(administratorEmail || 'A').charAt(0).toUpperCase());
  const administratorPicture = safeHttpsImageUrl(administratorPictureUrl);
  const administratorHeaderAvatar = administratorPicture
    ? `<img class="profile-image" src="${escapeHtml(administratorPicture)}" alt="">`
    : `<span>${administratorInitial}</span>`;
  const administratorMenuAvatar = administratorPicture
    ? `<img class="profile-avatar profile-image" src="${escapeHtml(administratorPicture)}" alt="">`
    : `<span class="profile-avatar">${administratorInitial}</span>`;
  const userRows = users.map(user => {
    const picture = safeHttpsImageUrl(user.picture_url);
    const initial = escapeHtml((user.display_name || user.email || '?').trim().charAt(0).toUpperCase());
    const adAccounts = Array.isArray(user.ad_accounts) ? user.ad_accounts : [];
    const assignedIds = adAccounts.map(account => String(account.id));
    const visibleAccounts = adAccounts.slice(0, 2);
    const hiddenAccountCount = Math.max(0, adAccounts.length - visibleAccounts.length);
    const accountBadges = visibleAccounts.map(account =>
      `<span class="account-badge ${account.allowed ? 'account-allowed' : 'account-denied'}">${escapeHtml(account.id)}</span>`
    ).join('') + (hiddenAccountCount > 0
      ? `<span class="account-badge account-more"><span class="technical-value" lang="en" dir="ltr">+${hiddenAccountCount}</span> زیاتر</span>`
      : '');
    return `<tr class="management-row" data-user-row data-search-value="${escapeHtml(`${user.display_name || ''} ${user.email || ''}`.toLowerCase())}">
      <td data-label="بەکارهێنەر"><div class="user-cell">${picture ? `<img src="${picture}" alt="">` : `<span class="user-avatar">${initial}</span>`}<div><strong>${escapeHtml(user.display_name) || 'بەکارهێنەری Google'}</strong><span class="technical-value" lang="en" dir="ltr">${escapeHtml(user.email)}</span></div></div></td>
      <td data-label="هەژمارە دیاریکراوەکان"><div class="account-badges">${accountBadges || '<span class="muted">هێشتا نییە</span>'}</div></td>
      <td data-label="بەشداری لە"><time class="technical-value" lang="en" dir="ltr" datetime="${escapeHtml(new Date(user.created_at).toISOString())}">${escapeHtml(formatDashboardDate(user.created_at))}</time></td>
      <td data-label="دوایین چالاکی"><time class="technical-value" lang="en" dir="ltr" datetime="${escapeHtml(new Date(user.last_seen_at).toISOString())}">${escapeHtml(formatDashboardDate(user.last_seen_at))}</time></td>
      <td class="actions" data-label="کردارەکان"><div class="user-row-actions"><button class="assign-button" type="button" data-assign-user data-user-id="${user.id}" data-user-name="${escapeHtml(user.display_name || 'بەکارهێنەری Google')}" data-user-email="${escapeHtml(user.email)}" data-assigned-accounts="${escapeHtml(JSON.stringify(assignedIds))}">${dashboardIcon('plus')}<span>دیاریکردنی هەژمارەکان</span></button><button class="delete-row-button" type="button" data-confirm-delete data-delete-action="${adminBasePath}/users/${user.id}/delete" data-delete-title="سڕینەوەی بەکارهێنەر" data-delete-message="ئەم بەکارهێنەرە و هەموو هەژمارە دیاریکراوەکانی دەسڕێنەوە. ئەم کردارە ناگەڕێتەوە." data-delete-target="${escapeHtml(user.email)}" aria-label="سڕینەوەی ${escapeHtml(user.email)}" title="سڕینەوە">${dashboardIcon('trash')}</button></div></td>
    </tr>`;
  }).join('');
  const accountOptions = accounts.map(account => `
    <div class="account-option ${account.enabled ? '' : 'is-disabled'}" data-account-option data-search-value="${escapeHtml(account.advertiser_id)}">
      <label class="account-option-select">
        <input type="checkbox" name="advertiserIds" value="${escapeHtml(account.advertiser_id)}" data-account-available="${account.enabled ? 'true' : 'false'}" ${account.enabled ? '' : 'disabled'}>
        <span class="account-option-check">${dashboardIcon('shield')}</span>
        <span class="account-option-copy"><strong>${escapeHtml(account.advertiser_id)}</strong><small>${account.enabled ? 'چالاک' : 'ناچالاک'}</small></span>
      </label>
      <span class="account-row-actions">
        <button type="button" data-edit-account data-account-id="${account.id}" data-advertiser-id="${escapeHtml(account.advertiser_id)}" aria-label="دەستکاریکردنی هەژمار" title="دەستکاریکردن">${dashboardIcon('edit')}</button>
        <button type="submit" formmethod="post" formaction="${adminBasePath}/accounts/${account.id}/toggle" formnovalidate aria-label="${account.enabled ? 'ناچالاککردنی هەژمار' : 'چالاککردنی هەژمار'}" title="${account.enabled ? 'ناچالاککردن' : 'چالاککردن'}">${dashboardIcon('power')}</button>
        <button class="danger" type="button" data-confirm-delete data-delete-action="${adminBasePath}/accounts/${account.id}/delete" data-delete-title="سڕینەوەی هەژماری ڕیکلامی" data-delete-message="ئەم هەژمارە لە هەموو بەکارهێنەرە دیاریکراوەکانیش لادەبرێت. ئەم کردارە ناگەڕێتەوە." data-delete-target="${escapeHtml(account.advertiser_id)}" aria-label="سڕینەوەی هەژمار" title="سڕینەوە">${dashboardIcon('trash')}</button>
      </span>
    </div>`).join('');
  const statistics = renderStatCardGrid([
    renderStatCard({ icon: dashboardIcon('users'), label: 'بەکارهێنەرانی Google', value: users.length, color: 'purple' }),
    renderStatCard({ icon: dashboardIcon('hash'), label: 'دیاریکردنی هەژمارەکان', value: assignedAccountCount, color: 'blue' }),
    renderStatCard({ icon: dashboardIcon('shield'), label: 'چالاک لەم هەفتەیە', value: recentUserCount, color: 'green' }),
    renderStatCard({ icon: dashboardIcon('ban'), label: 'بێ هەژماری دیاریکراو', value: unassignedUserCount, color: 'pink' }),
    renderStatCard({ icon: dashboardIcon('hash'), label: 'هەژمارە ڕیکلامییەکان', value: accounts.length, color: 'orange' }),
    renderStatCard({ icon: dashboardIcon('shield'), label: 'هەژمارە چالاکەکان', value: enabledAccountCount, color: 'cyan' })
  ], { columns: 3, className: 'dashboard-statistics' });

  return `<!doctype html>
  <html lang="ckb" dir="ltr">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Sponsor.krd Extension</title>
      <link rel="icon" type="image/png" href="${adminBasePath}/logo.png">
      <link rel="stylesheet" href="${adminBasePath}/admin.css">
      <script src="${adminBasePath}/admin.js" defer></script>
    </head>
    <body class="dashboard-page">
      <button class="sidebar-backdrop" type="button" data-sidebar-close aria-label="داخستنی لاتەنیشت"></button>
      <div class="dashboard-shell">
        <aside class="sidebar" id="dashboard-sidebar">
          <div class="sidebar-brand">
            <img src="${adminBasePath}/logo.png" alt="Sponsor.krd Extension">
            <div class="sidebar-brand-copy"><strong>Sponsor.krd Extension</strong><span>کۆنترۆڵی دەستگەیشتن</span></div>
            <button class="sidebar-close" type="button" data-sidebar-close aria-label="داخستنی لاتەنیشت">${dashboardIcon('close')}</button>
          </div>
          <nav aria-label="ڕێنیشاندەری پانێڵ">
            <a class="nav-item active" href="#users" data-nav-item title="بەڕێوەبردنی بەکارهێنەران">${dashboardIcon('users')}<span>بەڕێوەبردنی بەکارهێنەران</span></a>
          </nav>
          <div class="sidebar-footer">${dashboardIcon('shield')}<span><strong>ناوچەی پارێزراو</strong><small>دەستگەیشتنی بەڕێوەبەر بە Google</small></span></div>
        </aside>

        <div class="dashboard-content">
          <header class="topbar">
            <div class="topbar-title">
              <button class="header-action" type="button" data-sidebar-toggle aria-label="کردنەوە یان داخستنی لاتەنیشت" title="کردنەوە یان داخستنی لاتەنیشت">${dashboardIcon('menu')}</button>
              <h1>بەڕێوەبردنی بەکارهێنەران</h1>
            </div>
            <div class="topbar-actions">
              <button class="header-action" type="button" data-refresh aria-label="نوێکردنەوەی زانیارییەکانی پانێڵ" title="نوێکردنەوە">${dashboardIcon('refresh')}</button>
              <button class="header-action" type="button" data-theme-toggle aria-label="گۆڕینی ڕووکار" title="گۆڕینی ڕووکار">${dashboardIcon('moon', 'theme-icon-moon')}${dashboardIcon('sun', 'theme-icon-sun')}</button>
              <div class="profile-menu">
                <button class="profile-trigger" type="button" data-profile-toggle aria-label="لیستی هەژماری بەڕێوەبەر" aria-expanded="false">${administratorHeaderAvatar}</button>
                <div class="profile-popover" data-profile-popover hidden>
                  <div class="profile-summary">${administratorMenuAvatar}<div><strong>بەڕێوەبەر</strong><small class="technical-value" lang="en" dir="ltr">${escapeHtml(administratorEmail)}</small></div><b>بەڕێوەبەر</b></div>
                  <form method="post" action="${adminBasePath}/logout">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <button class="profile-action danger-text" type="submit">${dashboardIcon('logout')}<span>چوونەدەرەوە</span></button>
                  </form>
                </div>
              </div>
            </div>
          </header>

          <main class="dashboard-main" id="users">
            ${statistics}

            <section class="surface-card table-panel users-management">
              <div class="section-header management-page-header">
                <div><span class="section-icon">${dashboardIcon('users')}</span><div><h2>بەکارهێنەران و دەستگەیشتن</h2><p>گەڕان لە بەکارهێنەران و بەڕێوەبردنی هەژمارە دیاریکراوەکان لە یەک شوێن.</p></div></div>
                <div class="page-actions">
                  <label class="search-control"><span>${dashboardIcon('users')}</span><input type="search" data-user-search placeholder="گەڕان بە ناو یان ئیمەیڵ…" aria-label="گەڕان لە بەکارهێنەران"></label>
                  <button class="toolbar-button" type="button" data-refresh aria-label="نوێکردنەوەی بەکارهێنەران" title="نوێکردنەوەی بەکارهێنەران">${dashboardIcon('refresh')}</button>
                </div>
              </div>
              <div class="table-wrap">
                <table class="management-table users-table">
                  <thead><tr><th>بەکارهێنەر</th><th>هەژمارە دیاریکراوەکان</th><th>بەشداری لە</th><th>دوایین چالاکی</th><th>کردارەکان</th></tr></thead>
                  <tbody>${userRows || `<tr><td colspan="5" class="empty"><span class="empty-icon">${dashboardIcon('users')}</span><strong>هێشتا هیچ بەکارهێنەرێک نییە</strong><small>بەکارهێنەران دوای چوونەژوورەوە بە Google لێرە دەردەکەون.</small></td></tr>`}</tbody>
                </table>
              </div>
              <div class="table-empty-filter" data-user-search-empty hidden>هیچ بەکارهێنەرێک لەگەڵ گەڕانەکەت ناگونجێت.</div>
            </section>
          </main>

          <div class="management-modal" data-assignment-modal hidden>
            <button class="modal-backdrop" type="button" data-modal-close aria-label="داخستنی پەنجەرەی دیاریکردن"></button>
            <form class="modal-surface" method="post" data-assignment-form data-action-base="${adminBasePath}/users/" data-assignment-limit="${maxAdvertiserAccountsPerUser}" role="dialog" aria-modal="true" aria-labelledby="assignment-modal-title" tabindex="-1">
              <header class="modal-header">
                <div><h2 id="assignment-modal-title">دیاریکردنی هەژمارە ڕیکلامییەکان</h2><p>هەژمارە پێویستەکان هەڵبژێرە.</p></div>
                <button class="modal-close" type="button" data-modal-close aria-label="داخستنی پەنجەرە">${dashboardIcon('close')}</button>
              </header>
              <div class="modal-progress"></div>
              <div class="modal-body">
                <div class="assignment-user"><span class="user-avatar" data-modal-user-initial>U</span><div><strong data-modal-user-name>بەکارهێنەری Google</strong><span class="technical-value" lang="en" dir="ltr" data-modal-user-email></span></div><span class="assignment-count-pill"><span class="technical-value" lang="en" dir="ltr" data-assignment-count>0 / ${maxAdvertiserAccountsPerUser}</span><small>دیاریکراو</small></span></div>
                <section class="modal-section">
                  <div class="modal-section-heading"><div><h3>هەژمارەکان</h3><p>تا 25 هەژمار دەتوانیت دیاری بکەیت.</p></div></div>
                  <label class="modal-account-search"><span>${dashboardIcon('search')}</span><input type="search" data-account-search placeholder="گەڕان بە ناسنامەی هەژمار…" aria-label="گەڕان لە هەژمارە ڕیکلامییەکان"></label>
                  <p class="assignment-limit-message" data-assignment-limit-message hidden>گەیشتیتە سنووری 25 هەژماری ڕیکلامی بۆ ئەم ئیمەیڵە.</p>
                  <div class="account-options">${accountOptions || `<div class="modal-empty">${dashboardIcon('hash')}<span>هێشتا هیچ هەژمارێکی ڕیکلامی نییە. یەکەم هەژمار لە خوارەوە زیاد بکە.</span></div>`}</div>
                  <p class="account-search-empty" data-account-search-empty hidden>هیچ هەژمارێک نەدۆزرایەوە.</p>
                </section>
                <section class="account-edit-panel" data-account-edit-panel data-action-base="${adminBasePath}/accounts/" hidden>
                  <div><h3>دەستکاریکردنی هەژمار</h3><button type="button" data-account-edit-close aria-label="داخستنی دەستکاری">${dashboardIcon('close')}</button></div>
                  <label>ناسنامەی هەژماری ڕیکلامی<input name="editedAdvertiserId" data-account-edit-input inputmode="numeric" pattern="[0-9]{5,32}" maxlength="32" required disabled></label>
                  <footer><button type="button" data-account-edit-close>هەڵوەشاندنەوە</button><button class="primary-button" type="submit" formmethod="post" data-account-edit-save>${dashboardIcon('shield')}<span>پاشەکەوتکردن</span></button></footer>
                </section>
                <button class="add-account-toggle" type="button" data-add-account-toggle aria-expanded="false">${dashboardIcon('plus')}<span>زیادکردنی هەژماری نوێ</span><span class="toggle-chevron">${dashboardIcon('chevronDown')}</span></button>
                <section class="new-account-panel" data-new-account-panel hidden>
                  <label>ناسنامەی هەژماری ڕیکلامی<input name="newAdvertiserId" inputmode="numeric" pattern="[0-9]{5,32}" maxlength="32" placeholder="1234567890123456789"></label>
                  <p>هەژمارەکە دەچالاکرێت و بۆ ئەم بەکارهێنەرە دیاری دەکرێت.</p>
                </section>
              </div>
              <footer class="modal-footer">
                <button class="modal-cancel" type="button" data-modal-close>هەڵوەشاندنەوە</button>
                <button class="primary-button modal-save" type="submit">${dashboardIcon('shield')}<span>پاشەکەوتکردن</span></button>
              </footer>
              <input type="hidden" name="_csrf" value="${csrfToken}">
            </form>
          </div>

          <div class="management-modal delete-modal" data-delete-modal hidden>
            <button class="modal-backdrop" type="button" data-delete-close aria-label="داخستنی پەنجەرەی سڕینەوە"></button>
            <section class="modal-surface delete-modal-surface" role="alertdialog" aria-modal="true" aria-labelledby="delete-modal-title" aria-describedby="delete-modal-message" tabindex="-1">
              <header class="modal-header delete-modal-header">
                <div class="delete-modal-heading"><span class="delete-modal-icon">${dashboardIcon('trash')}</span><div><h2 id="delete-modal-title" data-delete-modal-title>دڵنیابوونەوە لە سڕینەوە</h2><p>پێش بەردەوامبوون وردببینەوە.</p></div></div>
                <button class="modal-close" type="button" data-delete-close aria-label="داخستنی پەنجەرە">${dashboardIcon('close')}</button>
              </header>
              <div class="modal-progress delete-progress"></div>
              <div class="delete-modal-body">
                <p id="delete-modal-message" data-delete-modal-message></p>
                <strong class="delete-modal-target technical-value" lang="en" dir="ltr" data-delete-modal-target></strong>
              </div>
              <footer class="modal-footer delete-modal-footer">
                <button class="modal-cancel" type="button" data-delete-close>هەڵوەشاندنەوە</button>
                <form method="post" data-delete-form>
                  <input type="hidden" name="_csrf" value="${csrfToken}">
                  <button class="delete-confirm-button" type="submit">${dashboardIcon('trash')}<span>سڕینەوە</span></button>
                </form>
              </footer>
            </section>
          </div>
        </div>
      </div>
    </body>
  </html>`;
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'postgresql' });
  } catch {
    res.status(503).json({ status: 'unavailable' });
  }
});

app.get('/api/v1/auth/google/start', userLoginLimiter, async (req, res, next) => {
  try {
    const extensionRedirectUri = String(req.query.redirect_uri || '');
    if (!isAllowedExtensionRedirect(extensionRedirectUri)) {
      res.status(400).type('text').send('Invalid extension redirect URL.');
      return;
    }

    const state = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(32).toString('base64url');
    await pool.query('DELETE FROM extension_oauth_states WHERE expires_at <= NOW()');
    await pool.query(
      `INSERT INTO extension_oauth_states (state_hash, nonce, extension_redirect_uri, expires_at)
       VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')`,
      [sha256(state), nonce, extensionRedirectUri]
    );

    res.redirect(302, googleUserOAuthClient.generateAuthUrl({
      access_type: 'online',
      include_granted_scopes: false,
      nonce,
      prompt: 'select_account',
      response_type: 'code',
      scope: ['openid', 'email', 'profile'],
      state
    }));
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/auth/google/callback', userLoginLimiter, async (req, res, next) => {
  const state = String(req.query.state || '');
  let extensionRedirectUri = '';
  try {
    if (!state) {
      res.status(400).type('text').send('Missing OAuth state.');
      return;
    }
    const stateResult = await pool.query(
      `DELETE FROM extension_oauth_states
        WHERE state_hash = $1 AND expires_at > NOW()
      RETURNING nonce, extension_redirect_uri`,
      [sha256(state)]
    );
    const loginState = stateResult.rows[0];
    if (!loginState || !isAllowedExtensionRedirect(loginState.extension_redirect_uri)) {
      res.status(400).type('text').send('The sign-in request is invalid or expired.');
      return;
    }
    extensionRedirectUri = loginState.extension_redirect_uri;
    if (req.query.error) {
      res.redirect(302, appendQuery(loginState.extension_redirect_uri, { error: 'access_denied' }));
      return;
    }

    const code = String(req.query.code || '');
    if (!code) {
      res.redirect(302, appendQuery(loginState.extension_redirect_uri, { error: 'missing_code' }));
      return;
    }

    const { tokens } = await googleUserOAuthClient.getToken({
      code,
      redirect_uri: googleUserRedirectUri.toString()
    });
    if (!tokens.id_token) throw new Error('Google did not return an ID token.');
    const ticket = await googleUserOAuthClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const googleSubject = String(payload?.sub || '');
    const email = String(payload?.email || '').trim().toLowerCase();
    const validIdentity = Boolean(googleSubject)
      && payload?.email_verified === true
      && Boolean(payload?.nonce)
      && safeEqual(payload.nonce, loginState.nonce);
    if (!validIdentity || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.redirect(302, appendQuery(loginState.extension_redirect_uri, { error: 'invalid_identity' }));
      return;
    }

    const userResult = await pool.query(
      `INSERT INTO extension_users (google_subject, email, display_name, picture_url)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (google_subject) DO UPDATE SET
         email = EXCLUDED.email,
         display_name = EXCLUDED.display_name,
         picture_url = EXCLUDED.picture_url,
         last_login_at = NOW(),
         last_seen_at = NOW()
       RETURNING id`,
      [googleSubject, email, String(payload?.name || '').slice(0, 200), String(payload?.picture || '').slice(0, 2000)]
    );
    const exchangeCode = crypto.randomBytes(32).toString('base64url');
    await pool.query('DELETE FROM extension_login_codes WHERE expires_at <= NOW()');
    await pool.query(
      `INSERT INTO extension_login_codes (code_hash, user_id, extension_redirect_uri, expires_at)
       VALUES ($1, $2, $3, NOW() + INTERVAL '2 minutes')`,
      [sha256(exchangeCode), userResult.rows[0].id, loginState.extension_redirect_uri]
    );
    res.redirect(302, appendQuery(loginState.extension_redirect_uri, { code: exchangeCode }));
  } catch (error) {
    console.error('Google extension-user login failed:', error?.message || error);
    if (isAllowedExtensionRedirect(extensionRedirectUri)) {
      res.redirect(302, appendQuery(extensionRedirectUri, { error: 'server_error' }));
      return;
    }
    next(error);
  }
});

app.use('/api/v1/auth/exchange', requireAllowedExtensionOrigin);
app.post('/api/v1/auth/exchange', userLoginLimiter, async (req, res, next) => {
  try {
    const code = String(req.body?.code || '');
    const extensionRedirectUri = String(req.body?.redirectUri || '');
    if (!/^[A-Za-z0-9_-]{32,256}$/.test(code) || !isAllowedExtensionRedirect(extensionRedirectUri)) {
      res.status(400).json({ error: 'Invalid sign-in response.' });
      return;
    }
    const result = await pool.query(
      `DELETE FROM extension_login_codes c
        USING extension_users u
        WHERE c.user_id = u.id
          AND c.code_hash = $1
          AND c.extension_redirect_uri = $2
          AND c.expires_at > NOW()
      RETURNING u.id, u.email, u.display_name, u.picture_url`,
      [sha256(code), extensionRedirectUri]
    );
    const user = result.rows[0];
    if (!user) {
      res.status(401).json({ error: 'The sign-in response is invalid or expired.' });
      return;
    }
    const sessionToken = crypto.randomBytes(48).toString('base64url');
    await pool.query(
      `INSERT INTO extension_sessions (token_hash, user_id, expires_at)
       VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 day'))`,
      [sha256(sessionToken), user.id, userSessionDays]
    );
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      token: sessionToken,
      user: { email: user.email, name: user.display_name, picture: user.picture_url }
    });
  } catch (error) {
    next(error);
  }
});

app.use('/api/v1/auth/me', requireAllowedExtensionOrigin);
app.get('/api/v1/auth/me', requireExtensionUser, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    user: {
      email: req.extensionUser.email,
      name: req.extensionUser.display_name,
      picture: req.extensionUser.picture_url
    }
  });
});

app.use('/api/v1/auth/logout', requireAllowedExtensionOrigin);
app.post('/api/v1/auth/logout', requireExtensionUser, async (req, res, next) => {
  try {
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    await pool.query('DELETE FROM extension_sessions WHERE token_hash = $1', [sha256(token)]);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.use('/api/v1/authorize', requireAllowedExtensionOrigin);
app.post('/api/v1/authorize', authorizationLimiter, requireExtensionUser, async (req, res, next) => {
  try {
    const advertiserId = String(req.body?.advertiserId || '').trim();
    if (!advertiserIdPattern.test(advertiserId)) {
      res.status(400).json({ allowed: false, message: 'Invalid advertiser ID.' });
      return;
    }
    const result = await pool.query(
      `SELECT a.enabled
         FROM allowed_ad_accounts a
         JOIN extension_user_account_assignments assignment
           ON assignment.advertiser_id = a.advertiser_id
        WHERE a.advertiser_id = $1 AND assignment.user_id = $2
        LIMIT 1`,
      [advertiserId, req.extensionUser.id]
    );
    const allowed = result.rows[0]?.enabled === true;
    await pool.query(
      `INSERT INTO extension_user_ad_accounts (user_id, advertiser_id, last_allowed)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, advertiser_id) DO UPDATE SET
         last_allowed = EXCLUDED.last_allowed,
         last_seen_at = NOW()`,
      [req.extensionUser.id, advertiserId, allowed]
    );
    res.setHeader('Cache-Control', 'no-store');
    res.json({ allowed });
  } catch (error) {
    next(error);
  }
});

app.use(adminBasePath, adminLimiter, (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.get(`${adminBasePath}/admin.css`, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.css')));
app.get(`${adminBasePath}/admin.js`, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.js')));
app.get(`${adminBasePath}/kurdish-font.ttf`, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'kurdish-font.ttf')));
app.get(`${adminBasePath}/logo.png`, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.png')));

app.get(adminBasePath, (req, res) => {
  res.redirect(303, hasAdminSession(req) ? `${adminBasePath}/dashboard` : `${adminBasePath}/login`);
});

app.get(`${adminBasePath}/login`, (req, res) => {
  if (hasAdminSession(req)) {
    res.redirect(303, `${adminBasePath}/dashboard`);
    return;
  }
  res.type('html').send(renderLoginPage());
});

app.get(`${adminBasePath}/google`, adminLoginLimiter, (req, res) => {
  if (hasAdminSession(req)) {
    res.redirect(303, `${adminBasePath}/dashboard`);
    return;
  }

  const state = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');
  setOAuthCookie(res, 'admin_oauth_state', state);
  setOAuthCookie(res, 'admin_oauth_nonce', nonce);
  res.redirect(302, googleOAuthClient.generateAuthUrl({
    access_type: 'online',
    include_granted_scopes: false,
    nonce,
    prompt: 'select_account',
    response_type: 'code',
    scope: ['openid', 'email', 'profile'],
    state
  }));
});

app.get(`${adminBasePath}/google/callback`, adminLoginLimiter, async (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const expectedState = cookies.admin_oauth_state;
  const expectedNonce = cookies.admin_oauth_nonce;
  clearOAuthCookies(res);

  try {
    if (req.query.error) {
      res.status(401).type('html').send(renderLoginPage('چوونەژوورەوە بە Google هەڵوەشایەوە.'));
      return;
    }

    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    if (!code || !state || !expectedState || !expectedNonce || !safeEqual(state, expectedState)) {
      res.status(400).type('html').send(renderLoginPage('داواکاری چوونەژوورەوە نادروستە یان کاتی بەسەرچووە.'));
      return;
    }

    const { tokens } = await googleOAuthClient.getToken({
      code,
      redirect_uri: googleRedirectUri.toString()
    });
    if (!tokens.id_token) throw new Error('Google did not return an ID token.');

    const ticket = await googleOAuthClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const email = String(payload?.email || '').trim().toLowerCase();
    const validIdentity = payload?.email_verified === true
      && Boolean(payload?.nonce)
      && safeEqual(payload.nonce, expectedNonce);
    if (!validIdentity || !adminGoogleEmails.has(email)) {
      res.status(403).type('html').send(renderLoginPage('ئەم هەژمارەی Google ڕێگەی بەڕێوەبەری پێ نەدراوە.'));
      return;
    }

    res.cookie('krd_admin_session', createAdminSessionToken(email, payload?.picture), {
      httpOnly: true,
      secure: isProduction,
      // Google returns from a cross-site OAuth flow; Lax allows the new session
      // cookie on the immediate same-site dashboard navigation.
      sameSite: 'lax',
      path: adminBasePath,
      maxAge: adminSessionHours * 60 * 60 * 1000
    });
    res.redirect(303, `${adminBasePath}/dashboard`);
  } catch (error) {
    console.error('Google administrator login failed:', error?.message || error);
    res.status(401).type('html').send(renderLoginPage('چوونەژوورەوە سەرکەوتوو نەبوو. دووبارە هەوڵ بدە.'));
  }
});

app.get(`${adminBasePath}/dashboard`, requireAdminSession, async (req, res, next) => {
  try {
    const [accountResult, userResult] = await Promise.all([
      pool.query('SELECT id, advertiser_id, enabled, note, created_at FROM allowed_ad_accounts ORDER BY created_at DESC'),
      pool.query(`
        SELECT u.id, u.email, u.display_name, u.picture_url, u.created_at, u.last_seen_at,
               COALESCE(
                 JSON_AGG(JSON_BUILD_OBJECT('id', assignment.advertiser_id, 'allowed', account.enabled)
                   ORDER BY assignment.created_at DESC) FILTER (WHERE assignment.advertiser_id IS NOT NULL),
                 '[]'::json
               ) AS ad_accounts
          FROM extension_users u
          LEFT JOIN extension_user_account_assignments assignment ON assignment.user_id = u.id
          LEFT JOIN allowed_ad_accounts account ON account.advertiser_id = assignment.advertiser_id
         GROUP BY u.id
         ORDER BY u.last_seen_at DESC
      `)
    ]);
    const csrfToken = createCsrfToken();
    setCsrfCookie(res, csrfToken);
    const administratorEmail = String(req.adminSession?.sub || '');
    const matchingExtensionUser = userResult.rows.find(user =>
      String(user.email || '').toLowerCase() === administratorEmail.toLowerCase()
    );
    res.type('html').send(renderAdminPage(
      accountResult.rows,
      userResult.rows,
      csrfToken,
      administratorEmail,
      String(req.adminSession?.picture || matchingExtensionUser?.picture_url || '')
    ));
  } catch (error) {
    next(error);
  }
});

app.post(`${adminBasePath}/logout`, requireAdminSession, requireCsrf, (req, res) => {
  res.clearCookie('krd_admin_session', { path: adminBasePath });
  res.clearCookie('admin_csrf', { path: adminBasePath });
  res.redirect(303, `${adminBasePath}/login`);
});

app.post(`${adminBasePath}/accounts`, requireAdminSession, requireCsrf, async (req, res, next) => {
  try {
    const advertiserId = String(req.body?.advertiserId || '').trim();
    const note = String(req.body?.note || '').trim().slice(0, 200);
    if (!advertiserIdPattern.test(advertiserId)) {
      res.status(400).type('text').send('ناسنامەی هەژماری ڕیکلامی دەبێت لە ٥ تا ٣٢ ژمارە پێک بێت.');
      return;
    }
    await pool.query(
      `INSERT INTO allowed_ad_accounts (advertiser_id, enabled, note)
       VALUES ($1, TRUE, $2)
       ON CONFLICT (advertiser_id)
       DO UPDATE SET enabled = TRUE, note = EXCLUDED.note, updated_at = NOW()`,
      [advertiserId, note]
    );
    res.redirect(303, `${adminBasePath}/dashboard`);
  } catch (error) {
    next(error);
  }
});

app.post(`${adminBasePath}/users/:id/assignments`, requireAdminSession, requireCsrf, async (req, res, next) => {
  const client = await pool.connect();
  try {
    if (!/^\d+$/.test(req.params.id)) {
      res.status(400).type('text').send('تۆماری بەکارهێنەر نادروستە.');
      return;
    }
    const submittedIds = Array.isArray(req.body?.advertiserIds)
      ? req.body.advertiserIds
      : req.body?.advertiserIds
        ? [req.body.advertiserIds]
        : [];
    const assignedIds = [...new Set(submittedIds.map(value => String(value).trim()).filter(Boolean))];
    const newAdvertiserId = String(req.body?.newAdvertiserId || '').trim();
    const newNote = String(req.body?.newNote || '').trim().slice(0, 200);
    if (assignedIds.some(value => !advertiserIdPattern.test(value)) || (newAdvertiserId && !advertiserIdPattern.test(newAdvertiserId))) {
      res.status(400).type('text').send('ناسنامەکانی هەژماری ڕیکلامی دەبێت لە ٥ تا ٣٢ ژمارە پێک بێت.');
      return;
    }
    const uniqueIds = [...new Set(newAdvertiserId ? [...assignedIds, newAdvertiserId] : assignedIds)];
    if (uniqueIds.length > maxAdvertiserAccountsPerUser) {
      res.status(400).type('text').send(`هەر ئیمەیڵێک تەنها دەتوانێت تا ${maxAdvertiserAccountsPerUser} هەژماری ڕیکلامی هەبێت.`);
      return;
    }

    await client.query('BEGIN');
    const userResult = await client.query('SELECT id FROM extension_users WHERE id = $1 LIMIT 1 FOR UPDATE', [req.params.id]);
    if (!userResult.rows[0]) {
      await client.query('ROLLBACK');
      res.status(404).type('text').send('بەکارهێنەری زیادکراوە نەدۆزرایەوە.');
      return;
    }
    if (newAdvertiserId) {
      await client.query(
        `INSERT INTO allowed_ad_accounts (advertiser_id, enabled, note)
         VALUES ($1, TRUE, $2)
         ON CONFLICT (advertiser_id) DO UPDATE SET enabled = TRUE, note = EXCLUDED.note, updated_at = NOW()`,
        [newAdvertiserId, newNote]
      );
    }
    if (uniqueIds.length > 0) {
      const validResult = await client.query(
        'SELECT advertiser_id FROM allowed_ad_accounts WHERE enabled = TRUE AND advertiser_id = ANY($1::text[])',
        [uniqueIds]
      );
      if (validResult.rows.length !== uniqueIds.length) {
        await client.query('ROLLBACK');
        res.status(400).type('text').send('یەک یان زیاتر لە هەژمارە ڕیکلامییەکان بەردەست نین. پەڕەکە نوێ بکەرەوە و دووبارە هەوڵ بدە.');
        return;
      }
    }
    await client.query('DELETE FROM extension_user_account_assignments WHERE user_id = $1', [req.params.id]);
    if (uniqueIds.length > 0) {
      await client.query(
        `INSERT INTO extension_user_account_assignments (user_id, advertiser_id)
         SELECT $1, UNNEST($2::text[])`,
        [req.params.id, uniqueIds]
      );
    }
    await client.query('COMMIT');
    res.redirect(303, `${adminBasePath}/dashboard#users`);
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    next(error);
  } finally {
    client.release();
  }
});

app.post(`${adminBasePath}/users/:id/delete`, requireAdminSession, requireCsrf, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) {
      res.status(400).type('text').send('تۆماری بەکارهێنەر نادروستە.');
      return;
    }
    const result = await pool.query('DELETE FROM extension_users WHERE id = $1 RETURNING id', [req.params.id]);
    if (!result.rows[0]) {
      res.status(404).type('text').send('بەکارهێنەرەکە نەدۆزرایەوە.');
      return;
    }
    res.redirect(303, `${adminBasePath}/dashboard#users`);
  } catch (error) {
    next(error);
  }
});

app.post(`${adminBasePath}/accounts/:id/toggle`, requireAdminSession, requireCsrf, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) {
      res.status(400).type('text').send('تۆماری هەژمار نادروستە.');
      return;
    }
    await pool.query(
      'UPDATE allowed_ad_accounts SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1',
      [req.params.id]
    );
    res.redirect(303, `${adminBasePath}/dashboard`);
  } catch (error) {
    next(error);
  }
});

app.post(`${adminBasePath}/accounts/:id/edit`, requireAdminSession, requireCsrf, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) {
      res.status(400).type('text').send('تۆماری هەژمار نادروستە.');
      return;
    }
    const advertiserId = String(req.body?.editedAdvertiserId || '').trim();
    if (!advertiserIdPattern.test(advertiserId)) {
      res.status(400).type('text').send('ناسنامەی هەژماری ڕیکلامی دەبێت لە ٥ تا ٣٢ ژمارە پێک بێت.');
      return;
    }
    const result = await pool.query(
      `UPDATE allowed_ad_accounts
          SET advertiser_id = $1, updated_at = NOW()
        WHERE id = $2
        RETURNING id`,
      [advertiserId, req.params.id]
    );
    if (!result.rows[0]) {
      res.status(404).type('text').send('هەژمارە ڕیکلامییەکە نەدۆزرایەوە.');
      return;
    }
    res.redirect(303, `${adminBasePath}/dashboard#users`);
  } catch (error) {
    if (error?.code === '23505') {
      res.status(409).type('text').send('ئەم ناسنامەی هەژمارە پێشتر هەیە.');
      return;
    }
    next(error);
  }
});

app.post(`${adminBasePath}/accounts/:id/delete`, requireAdminSession, requireCsrf, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) {
      res.status(400).type('text').send('تۆماری هەژمار نادروستە.');
      return;
    }
    await pool.query('DELETE FROM allowed_ad_accounts WHERE id = $1', [req.params.id]);
    res.redirect(303, `${adminBasePath}/dashboard`);
  } catch (error) {
    next(error);
  }
});

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
app.use((error, _req, res, _next) => {
  console.error('Request failed:', error?.message || error);
  res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(port, host, () => {
  console.log(`Authorization backend listening on http://${host}:${port}`);
});

async function shutdown(signal) {
  console.log(`${signal} received, shutting down.`);
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
