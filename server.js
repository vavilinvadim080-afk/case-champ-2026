/**
 * Кейс-Чемпионат 2026 — сервер
 *
 * Запуск:   npm install && npm start
 * Откроет:  http://localhost:3000
 *
 * Стек:
 *   - Express         (HTTP + роуты + статика)
 *   - node:sqlite     (встроенный SQLite, Node 22.5+, без нативных модулей)
 *   - multer          (приём multipart/form-data, лимит файла на уровне сервера)
 *   - node:crypto     (scrypt-хэши паролей, uuid-токены сессий)
 *
 * Данные на диске:
 *   data/app.db                 — SQLite-база
 *   data/uploads/<timestamp>_*  — PDF-решения
 */

'use strict';

const path     = require('node:path');
const fs       = require('node:fs');
const crypto   = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const express  = require('express');
const multer   = require('multer');

/* ==========================================================================
   Конфигурация (можно переопределить через переменные окружения)
   ========================================================================== */
const PORT             = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR         = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS_DIR      = path.join(DATA_DIR, 'uploads');
const DB_FILE          = path.join(DATA_DIR, 'app.db');
const MAX_FILE_MB      = parseInt(process.env.MAX_FILE_MB || '25', 10);
const MAX_FILE_BYTES   = MAX_FILE_MB * 1024 * 1024;
const SESSION_TTL_MS   = 30 * 24 * 60 * 60 * 1000; // 30 дней

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
   Криптография
   ========================================================================== */
function hashPassword(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pass, salt, 64).toString('hex');
  return { hash, salt };
}
function verifyPassword(pass, hash, salt) {
  try {
    const test = crypto.scryptSync(pass, salt, 64);
    const stored = Buffer.from(hash, 'hex');
    return test.length === stored.length && crypto.timingSafeEqual(test, stored);
  } catch { return false; }
}
function newToken() { return crypto.randomBytes(32).toString('hex'); }

/* ==========================================================================
   Multer — приём файла с лимитами
   ========================================================================== */
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const safe = (file.originalname || 'solution.pdf')
      .normalize('NFKD')
      .replace(/[^\w.\-]+/g, '_')
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

/* ==========================================================================
   Express
   ========================================================================== */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

/* Раздача клиента */
app.use(express.static(__dirname, { index: 'index.html', extensions: ['html'] }));

/* Конфиг для клиента (чтобы не дублировать константы) */
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
app.post('/api/register', (req, res) => {
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
  if (team.length > 60)
    return res.status(400).json({ error: 'Название команды слишком длинное' });

  const exists = db.prepare('SELECT 1 FROM users WHERE email = ?').get(email);
  if (exists) return res.status(409).json({ error: 'Пользователь с таким email уже зарегистрирован' });

  const { hash, salt } = hashPassword(password);
  db.prepare(`
    INSERT INTO users (email, name, university, team, pass_hash, pass_salt, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(email, name, university || null, team || null, hash, salt, Date.now());

  const token = newToken();
  db.prepare('INSERT INTO sessions (token, user_email, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(token, email, Date.now(), Date.now() + SESSION_TTL_MS);

  res.json({ ok: true, token, user: { email, name, university, team } });
});

/* ---- Вход ---- */
app.post('/api/login', (req, res) => {
  const email    = (req.body?.email    || '').trim().toLowerCase();
  const password = req.body?.password  || '';
  if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });

  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!u || !verifyPassword(password, u.pass_hash, u.pass_salt))
    return res.status(401).json({ error: 'Неверный email или пароль' });

  const token = newToken();
  db.prepare('INSERT INTO sessions (token, user_email, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(token, email, Date.now(), Date.now() + SESSION_TTL_MS);

  res.json({ ok: true, token, user: { email: u.email, name: u.name, university: u.university, team: u.team } });
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

/* ---- Обновить команду (если не указана при регистрации) ---- */
app.post('/api/me/team', auth, (req, res) => {
  const team = (req.body?.team || '').trim();
  if (team.length < 2 || team.length > 60)
    return res.status(400).json({ error: 'Название команды — 2–60 символов' });
  db.prepare('UPDATE users SET team = ? WHERE email = ?').run(team, req.userEmail);
  res.json({ ok: true, team });
});

/* ---- Отправить решение ---- */
app.post('/api/submission', auth, (req, res, next) => {
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
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });

  const team  = (req.body?.team  || u.team || '').trim();
  const title = (req.body?.title || '').trim();
  const notes = (req.body?.notes || '').trim().slice(0, 2000);

  if (!team)  return cleanupAndFail(req, res, 400, 'Укажи название команды');
  if (!title) return cleanupAndFail(req, res, 400, 'Укажи название решения');
  if (!req.file) return cleanupAndFail(req, res, 400, 'Прикрепи PDF-файл с решением');

  // Если у пользователя ещё не была указана команда — запишем
  if (!u.team) db.prepare('UPDATE users SET team = ? WHERE email = ?').run(team, req.userEmail);

  const info = db.prepare(`
    INSERT INTO submissions (team, user_email, title, notes, file_name, file_path, file_size, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'Принято', ?)
  `).run(team, req.userEmail, title, notes, req.file.originalname, path.basename(req.file.path), req.file.size, Date.now());

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
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'bad id' });

  const u = db.prepare('SELECT team FROM users WHERE email = ?').get(req.userEmail);
  const sub = db.prepare('SELECT * FROM submissions WHERE id = ?').get(id);
  if (!sub) return res.status(404).json({ error: 'Решение не найдено' });
  if (!u || u.team !== sub.team) return res.status(403).json({ error: 'Доступ только участникам команды' });

  const filePath = path.join(UPLOADS_DIR, sub.file_path);
  if (!fs.existsSync(filePath)) return res.status(410).json({ error: 'Файл удалён с диска' });

  res.download(filePath, sub.file_name);
});

/* ---- Health ---- */
app.get('/api/health', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

/* ---- 404 для /api/* ---- */
app.use('/api', (_req, res) => res.status(404).json({ error: 'Не найдено' }));

/* ==========================================================================
   Global error handler — последняя линия обороны, чтобы сервер не падал
   ========================================================================== */
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error('[unhandled]', err);
  if (res.headersSent) return;
  if (err && err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ error: `Файл больше ${MAX_FILE_MB} МБ` });
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

process.on('uncaughtException', e => console.error('[uncaught]', e));
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));

/* ==========================================================================
   Start
   ========================================================================== */
app.listen(PORT, () => {
  console.log(`\n  ▶ Кейс-Чемпионат 2026`);
  console.log(`  ▶ http://localhost:${PORT}`);
  console.log(`  ▶ Лимит файла: ${MAX_FILE_MB} МБ`);
  console.log(`  ▶ БД:         ${DB_FILE}`);
  console.log(`  ▶ Файлы:      ${UPLOADS_DIR}\n`);
});
