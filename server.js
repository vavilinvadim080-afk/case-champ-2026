/**
 * Кейс-Чемпионат 2026 — сервер
 *
 * Запуск:   npm install && npm start
 * Откроет:  http://localhost:3000
 *
 * Стек:
 *   - Express              (HTTP + роуты)
 *   - helmet               (security headers + CSP)
 *   - express-rate-limit   (защита от брутфорса)
 *   - node:sqlite          (встроенный SQLite, Node 22.5+)
 *   - multer               (приём multipart/form-data)
 *   - node:crypto (scrypt) (хэши паролей, токены сессий)
 *
 * Данные на диске:
 *   data/app.db                 — SQLite-база
 *   data/uploads/<timestamp>_*  — PDF-решения
 *
 * Статика (HTML/CSS/JS/SVG) лежит в `public/`. Корень проекта
 * НЕ раздаётся — иначе утекли бы server.js, package.json, БД.
 */

'use strict';

const path     = require('node:path');
const fs       = require('node:fs');
const crypto   = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
const express  = require('express');
const multer   = require('multer');
const helmet   = require('helmet');
const rateLimit = require('express-rate-limit');

const scryptAsync = promisify(crypto.scrypt);

/* ==========================================================================
   Конфигурация (можно переопределить через переменные окружения)
   ========================================================================== */
const PORT             = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR         = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS_DIR      = path.join(DATA_DIR, 'uploads');
const DB_FILE          = path.join(DATA_DIR, 'app.db');
const PUBLIC_DIR       = path.join(__dirname, 'public');
const MAX_FILE_MB      = parseInt(process.env.MAX_FILE_MB || '25', 10);
const MAX_FILE_BYTES   = MAX_FILE_MB * 1024 * 1024;
const KEEP_REVISIONS   = parseInt(process.env.KEEP_REVISIONS || '5', 10);
const SESSION_TTL_MS   = 30 * 24 * 60 * 60 * 1000; // 30 дней
const SCRYPT_N         = 16384; // дефолт scrypt — баланс безопасность/CPU

/* ==========================================================================
   Bootstrap: каталоги и БД
   ========================================================================== */
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const db = new DatabaseSync(DB_FILE);
db.exec(`
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    email       TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    university  TEXT,
    team        TEXT,
    pass_hash   TEXT NOT NULL,
    pass_salt   TEXT NOT NULL,
    created_at  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    team        TEXT NOT NULL,
    user_email  TEXT NOT NULL,
    title       TEXT NOT NULL,
    notes       TEXT,
    file_name   TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    file_size   INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Принято',
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (user_email) REFERENCES users(email)
  );
  CREATE INDEX IF NOT EXISTS idx_sub_team    ON submissions(team);
  CREATE INDEX IF NOT EXISTS idx_sub_created ON submissions(created_at DESC);

  CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_email  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    FOREIGN KEY (user_email) REFERENCES users(email)
  );
  CREATE INDEX IF NOT EXISTS idx_sess_exp ON sessions(expires_at);
`);

/* Простой housekeeping — раз в час чистим протухшие сессии */
setInterval(() => {
  try { db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()); }
  catch (e) { console.error('[sessions cleanup]', e.message); }
}, 60 * 60 * 1000).unref();

/* ==========================================================================
   Криптография (async + timing-safe)
   ========================================================================== */
async function hashPassword(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  const buf  = await scryptAsync(pass, salt, 64, { N: SCRYPT_N });
  return { hash: buf.toString('hex'), salt };
}

async function verifyPassword(pass, hash, salt) {
  try {
    const test   = await scryptAsync(pass, salt, 64, { N: SCRYPT_N });
    const stored = Buffer.from(hash, 'hex');
    return test.length === stored.length && crypto.timingSafeEqual(test, stored);
  } catch { return false; }
}

function newToken() { return crypto.randomBytes(32).toString('hex'); }

/* Dummy hash — для защиты от timing-атаки enumeration email.
   На login всегда делаем scrypt, даже если юзер не найден. */
const DUMMY = (() => {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync('timing-attack-protection', salt, 64, { N: SCRYPT_N }).toString('hex');
  return { hash, salt };
})();

/* ==========================================================================
   Multer — приём файла с лимитами
   ========================================================================== */
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const safe = (file.originalname || 'solution.pdf')
      .normalize('NFKD')
      .replace(/[^\w.\-]+/g, '_')
      .replace(/\.{2,}/g, '.')
      .slice(0, 80);
    cb(null, Date.now() + '_' + safe);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => {
    const isPdf =
      file.mimetype === 'application/pdf' ||
      /\.pdf$/i.test(file.originalname || '');
    if (isPdf) return cb(null, true);
    const err = new Error('Принимаем только PDF');
    err.code = 'BAD_MIME';
    cb(err);
  }
});

/* Magic bytes — проверяем содержимое файла, а не доверяем mimetype/расширению.
   PDF spec 7.5.2: подпись `%PDF-` должна встретиться в первых 1024 байтах. */
function isPdfMagic(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(1024);
    const bytesRead = fs.readSync(fd, buf, 0, 1024, 0);
    return buf.slice(0, bytesRead).includes('%PDF-');
  } catch {
    return false;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
  }
}

/* ==========================================================================
   Express + middleware безопасности
   ========================================================================== */
const app = express();
app.disable('x-powered-by');

// Railway/Timeweb-edge кладут реальный IP в X-Forwarded-For
app.set('trust proxy', 1);

/* helmet: security headers + CSP.
   'unsafe-inline' для style/script — потому что у нас inline CSS/JS в index.html.
   Можно убрать, если позже вынесем <style>/<script> во внешние файлы. */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:       ["'self'", "https://fonts.gstatic.com"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc:        ["'self'", "data:"],
      connectSrc:    ["'self'"],
      frameAncestors:["'none'"],
      objectSrc:     ["'none'"],
      baseUri:       ["'self'"],
      formAction:    ["'self'"],
    }
  },
  crossOriginResourcePolicy: { policy: "same-origin" },
  crossOriginOpenerPolicy:   { policy: "same-origin" },
  referrerPolicy:            { policy: "strict-origin-when-cross-origin" },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: false }
}));

app.use(express.json({ limit: '32kb' }));

/* Defense in depth: даже если кто-то случайно положит файл в корень — не отдадим */
app.use((req, _res, next) => {
  // Нормализуем путь, чтобы поймать "/./data" и "/../data" попытки
  const p = path.posix.normalize(req.path);
  if (/^\/(data|node_modules|\.git|server\.js|package(-lock)?\.json|README\.md|\.gitignore|\.env)/i.test(p)) {
    const err = new Error('Not found');
    err.status = 404;
    return next(err);
  }
  next();
});

/* ---- Rate limiters ---- */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 минут
  max: 8,                      // не больше 8 попыток
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много попыток входа. Подожди 15 минут.' },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,   // 1 час
  max: 5,                      // 5 регистраций с IP в час
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много регистраций с этого IP. Попробуй позже.' },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,   // 1 час
  max: 30,                     // 30 загрузок/час
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много загрузок. Подожди час.' },
});

/* ---- Раздача клиента (только из public/) ---- */
app.use(express.static(PUBLIC_DIR, {
  index: 'index.html',
  extensions: ['html'],
  dotfiles: 'deny',
  maxAge: '1h',
}));

/* ---- Конфиг для клиента ---- */
app.get('/api/config', (_req, res) => {
  res.json({ maxFileMB: MAX_FILE_MB });
});

/* ---- Auth middleware ---- */
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Требуется вход' });
  const row = db.prepare(
    'SELECT user_email FROM sessions WHERE token = ? AND expires_at > ?'
  ).get(token, Date.now());
  if (!row) return res.status(401).json({ error: 'Сессия истекла, войди заново' });
  req.userEmail = row.user_email;
  next();
}

/* ---- Регистрация ---- */
app.post('/api/register', registerLimiter, async (req, res, next) => {
  try {
    let { email, name, university, team, password } = req.body || {};
    email = (email || '').trim().toLowerCase();
    name  = (name  || '').trim();
    university = (university || '').trim();
    team = (team || '').trim();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Некорректный email' });
    if (name.length < 2 || name.length > 80)
      return res.status(400).json({ error: 'Укажи имя (2–80 символов)' });
    if (!password || password.length < 6)
      return res.status(400).json({ error: 'Пароль должен быть от 6 символов' });
    if (password.length > 200)
      return res.status(400).json({ error: 'Пароль слишком длинный' });
    if (team.length > 60)
      return res.status(400).json({ error: 'Название команды слишком длинное' });
    if (university.length > 120)
      return res.status(400).json({ error: 'Название вуза слишком длинное' });

    const exists = db.prepare('SELECT 1 FROM users WHERE email = ?').get(email);
    if (exists) return res.status(409).json({ error: 'Пользователь с таким email уже зарегистрирован' });

    const { hash, salt } = await hashPassword(password);
    db.prepare(`
      INSERT INTO users (email, name, university, team, pass_hash, pass_salt, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(email, name, university || null, team || null, hash, salt, Date.now());

    const token = newToken();
    db.prepare('INSERT INTO sessions (token, user_email, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .run(token, email, Date.now(), Date.now() + SESSION_TTL_MS);

    res.json({ ok: true, token, user: { email, name, university, team } });
  } catch (e) { next(e); }
});

/* ---- Вход (timing-safe: всегда выполняем scrypt) ---- */
app.post('/api/login', loginLimiter, async (req, res, next) => {
  try {
    const email    = (req.body?.email    || '').trim().toLowerCase();
    const password = req.body?.password  || '';
    if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });
    if (password.length > 200) return res.status(401).json({ error: 'Неверный email или пароль' });

    const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    // Защита от timing-атаки: всегда выполняем scrypt, даже если юзера нет —
    // иначе атакующий по времени ответа перечислит зарегистрированные email.
    let valid = false;
    if (u) {
      valid = await verifyPassword(password, u.pass_hash, u.pass_salt);
    } else {
      await verifyPassword(password, DUMMY.hash, DUMMY.salt);
    }

    if (!u || !valid)
      return res.status(401).json({ error: 'Неверный email или пароль' });

    const token = newToken();
    db.prepare('INSERT INTO sessions (token, user_email, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .run(token, email, Date.now(), Date.now() + SESSION_TTL_MS);

    res.json({ ok: true, token, user: { email: u.email, name: u.name, university: u.university, team: u.team } });
  } catch (e) { next(e); }
});

/* ---- Выход ---- */
app.post('/api/logout', auth, (req, res) => {
  const token = (req.headers.authorization || '').slice(7);
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.json({ ok: true });
});

/* ---- Профиль + статус команды ---- */
app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('SELECT email, name, university, team, created_at FROM users WHERE email = ?').get(req.userEmail);
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });

  let latest = null;
  let count  = 0;
  if (u.team) {
    latest = db.prepare(`
      SELECT id, team, user_email, title, notes, file_name, file_size, status, created_at
      FROM submissions WHERE team = ?
      ORDER BY created_at DESC LIMIT 1
    `).get(u.team);
    count = db.prepare('SELECT COUNT(*) AS c FROM submissions WHERE team = ?').get(u.team).c;
  }

  res.json({ user: u, team: { name: u.team, latest, totalSubmissions: count } });
});

/* ---- Обновить команду ---- */
app.post('/api/me/team', auth, (req, res) => {
  const team = (req.body?.team || '').trim();
  if (team.length < 2 || team.length > 60)
    return res.status(400).json({ error: 'Название команды — 2–60 символов' });
  db.prepare('UPDATE users SET team = ? WHERE email = ?').run(team, req.userEmail);
  res.json({ ok: true, team });
});

/* ---- Отправить решение ---- */
app.post('/api/submission', auth, uploadLimiter, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE')
        return res.status(413).json({ error: `Файл больше ${MAX_FILE_MB} МБ — сожми PDF` });
      if (err.code === 'BAD_MIME')
        return res.status(415).json({ error: err.message });
      return res.status(400).json({ error: err.message || 'Ошибка загрузки' });
    }
    next();
  });
}, (req, res) => {
  const u = db.prepare('SELECT team FROM users WHERE email = ?').get(req.userEmail);
  if (!u) return cleanupAndFail(req, res, 404, 'Пользователь не найден');

  const team  = (req.body?.team  || u.team || '').trim();
  const title = (req.body?.title || '').trim().slice(0, 200);
  const notes = (req.body?.notes || '').trim().slice(0, 2000);

  if (!team || team.length > 60)   return cleanupAndFail(req, res, 400, 'Укажи название команды (до 60 символов)');
  if (!title)                       return cleanupAndFail(req, res, 400, 'Укажи название решения');
  if (!req.file)                    return cleanupAndFail(req, res, 400, 'Прикрепи PDF-файл с решением');

  // Не доверяем mimetype/расширению — проверяем содержимое
  if (!isPdfMagic(req.file.path))   return cleanupAndFail(req, res, 415, 'Файл не похож на PDF — нужен реальный PDF, а не переименованный документ');

  // Если у пользователя ещё не была указана команда — запишем
  if (!u.team) db.prepare('UPDATE users SET team = ? WHERE email = ?').run(team, req.userEmail);

  // file_path сохраняем как basename — никаких '../' в БД
  const safePath = path.basename(req.file.path);

  const info = db.prepare(`
    INSERT INTO submissions (team, user_email, title, notes, file_name, file_path, file_size, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'Принято', ?)
  `).run(team, req.userEmail, title, notes, req.file.originalname, safePath, req.file.size, Date.now());

  // Хранить только последние KEEP_REVISIONS ревизий команды.
  // Старше — удаляем и файл с диска, и запись из БД.
  // LIMIT -1 OFFSET N в SQLite = «все строки, кроме первых N».
  const stale = db.prepare(`
    SELECT id, file_path FROM submissions
    WHERE team = ?
    ORDER BY created_at DESC
    LIMIT -1 OFFSET ?
  `).all(team, KEEP_REVISIONS);

  for (const s of stale) {
    const oldFile = path.join(UPLOADS_DIR, path.basename(s.file_path));
    try { fs.unlinkSync(oldFile); } catch {}
    db.prepare('DELETE FROM submissions WHERE id = ?').run(s.id);
  }

  const row = db.prepare(`
    SELECT id, team, user_email, title, notes, file_name, file_size, status, created_at
    FROM submissions WHERE id = ?
  `).get(info.lastInsertRowid);

  res.json({ ok: true, submission: row });
});

function cleanupAndFail(req, res, status, msg) {
  if (req.file && req.file.path) { try { fs.unlinkSync(req.file.path); } catch {} }
  return res.status(status).json({ error: msg });
}

/* ---- Список отправок команды ---- */
app.get('/api/submissions', auth, (req, res) => {
  const u = db.prepare('SELECT team FROM users WHERE email = ?').get(req.userEmail);
  if (!u || !u.team) return res.json({ submissions: [] });
  const rows = db.prepare(`
    SELECT id, team, user_email, title, notes, file_name, file_size, status, created_at
    FROM submissions WHERE team = ?
    ORDER BY created_at DESC
  `).all(u.team);
  res.json({ submissions: rows });
});

/* ---- Скачать файл решения ---- */
app.get('/api/submission/:id/download', auth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: 'bad id' });

  const u = db.prepare('SELECT team FROM users WHERE email = ?').get(req.userEmail);
  const sub = db.prepare('SELECT * FROM submissions WHERE id = ?').get(id);
  if (!sub) return res.status(404).json({ error: 'Решение не найдено' });
  if (!u || u.team !== sub.team) return res.status(403).json({ error: 'Доступ только участникам команды' });

  // Path traversal defense — file_path должен быть просто именем файла,
  // никаких '/', '\', '..' не пропускаем
  const fileBase = path.basename(sub.file_path);
  if (fileBase !== sub.file_path) return res.status(400).json({ error: 'invalid path' });
  const filePath = path.join(UPLOADS_DIR, fileBase);
  if (!filePath.startsWith(UPLOADS_DIR + path.sep))
    return res.status(400).json({ error: 'invalid path' });
  if (!fs.existsSync(filePath)) return res.status(410).json({ error: 'Файл удалён с диска' });

  res.download(filePath, sub.file_name);
});

/* ---- Health ---- */
app.get('/api/health', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

/* ---- 404 для /api/* ---- */
app.use('/api', (_req, res) => res.status(404).json({ error: 'Не найдено' }));

/* ==========================================================================
   Global error handler — последняя линия обороны
   Не светим стек/детали наружу.
   ========================================================================== */
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (err && err.status === 404) return res.status(404).end();
  console.error('[unhandled]', err);
  if (res.headersSent) return;
  if (err && err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ error: `Файл больше ${MAX_FILE_MB} МБ` });
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

process.on('uncaughtException',  e => console.error('[uncaught]', e));
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));

/* ==========================================================================
   Start
   ========================================================================== */
app.listen(PORT, () => {
  console.log(`\n  ▶ Кейс-Чемпионат 2026`);
  console.log(`  ▶ http://localhost:${PORT}`);
  console.log(`  ▶ Лимит файла: ${MAX_FILE_MB} МБ`);
  console.log(`  ▶ Public:     ${PUBLIC_DIR}`);
  console.log(`  ▶ БД:         ${DB_FILE}`);
  console.log(`  ▶ Файлы:      ${UPLOADS_DIR}\n`);
});
