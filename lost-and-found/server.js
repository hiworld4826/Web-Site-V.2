const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 }
}));

// ---------- อัปโหลดรูป ----------
const MIME_EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif', 'image/webp': '.webp' };
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, crypto.randomUUID() + MIME_EXT[file.mimetype])
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    MIME_EXT[file.mimetype] ? cb(null, true) : cb(new Error('รองรับเฉพาะไฟล์ JPG, PNG, GIF, WEBP'))
});
const handleUpload = (req, res, next) =>
  upload.single('image')(req, res, (err) => {
    if (err) {
      flash(req, 'error', 'อัปโหลดรูปไม่สำเร็จ: ' + (err.code === 'LIMIT_FILE_SIZE' ? 'ไฟล์ใหญ่เกิน 5MB' : err.message));
      return res.redirect(req.get('Referrer') || '/');
    }
    next();
  });
const removeImage = (name) => { if (name) fs.unlink(path.join(UPLOAD_DIR, name), () => {}); };

// ---------- Helpers ----------
function flash(req, type, msg) { req.session.flash = { type, msg }; }

function log(userId, action, detail = '') {
  db.prepare('INSERT INTO logs (user_id, action, detail) VALUES (?, ?, ?)').run(userId, action, detail);
}

function parseTags(str) {
  return [...new Set(
    String(str || '').split(/[,#]+/).map(t => t.trim().toLowerCase()).filter(Boolean)
  )].slice(0, 10);
}

const setItemTags = db.transaction((itemId, tags) => {
  db.prepare('DELETE FROM item_tags WHERE item_id = ?').run(itemId);
  for (const name of tags) {
    db.prepare('INSERT OR IGNORE INTO tags (name) VALUES (?)').run(name);
    const tag = db.prepare('SELECT id FROM tags WHERE name = ?').get(name);
    db.prepare('INSERT OR IGNORE INTO item_tags (item_id, tag_id) VALUES (?, ?)').run(itemId, tag.id);
  }
});

const cleanupTags = () =>
  db.prepare('DELETE FROM tags WHERE id NOT IN (SELECT DISTINCT tag_id FROM item_tags)').run();

function attachTags(items) {
  if (!items.length) return items;
  const rows = db.prepare(
    `SELECT it.item_id, t.name FROM item_tags it JOIN tags t ON t.id = it.tag_id
     WHERE it.item_id IN (${items.map(() => '?').join(',')})`
  ).all(...items.map(i => i.id));
  const map = {};
  rows.forEach(r => (map[r.item_id] ||= []).push(r.name));
  items.forEach(i => (i.tags = map[i.id] || []));
  return items;
}

function readItemForm(body) {
  const clean = (v, max) => String(v || '').trim().slice(0, max);
  return {
    type: body.type === 'found' ? 'found' : 'lost',
    title: clean(body.title, 100),
    description: clean(body.description, 2000),
    location: clean(body.location, 200),
    event_date: clean(body.event_date, 20),
    contact: clean(body.contact, 200)
  };
}

const safeRedirect = (url, fallback) =>
  typeof url === 'string' && /^\/(?![\/\\])/.test(url) ? url : fallback;

const canManage = (user, item) => !!user && (user.role === 'admin' || user.id === item.user_id);

// ---------- Middleware ----------
app.use((req, res, next) => {
  res.locals.user = null;
  if (req.session.userId) {
    res.locals.user = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(req.session.userId) || null;
    if (!res.locals.user) delete req.session.userId;
  }
  res.locals.flash = req.session.flash;
  delete req.session.flash;
  next();
});

function requireLogin(req, res, next) {
  if (res.locals.user) return next();
  flash(req, 'error', 'กรุณาเข้าสู่ระบบก่อน');
  res.redirect('/login');
}
function requireAdmin(req, res, next) {
  if (res.locals.user?.role === 'admin') return next();
  res.status(403).render('error', { message: 'หน้านี้สำหรับผู้ดูแลระบบเท่านั้น' });
}
function loadItem(req, res, next) {
  const item = db.prepare(
    'SELECT i.*, u.username FROM items i JOIN users u ON u.id = i.user_id WHERE i.id = ?'
  ).get(req.params.id);
  if (!item) return res.status(404).render('error', { message: 'ไม่พบรายการนี้' });
  req.item = attachTags([item])[0];
  next();
}
function requireOwner(req, res, next) {
  if (canManage(res.locals.user, req.item)) return next();
  res.status(403).render('error', { message: 'คุณไม่มีสิทธิ์จัดการรายการนี้' });
}
function loginUser(req, userId, cb) {
  req.session.regenerate(err => {
    if (err) return cb(err);
    req.session.userId = userId;
    cb();
  });
}

// ---------- หน้าแรก + ค้นหา ----------
app.get('/', (req, res) => {
  const q = String(req.query.q || '').trim();
  const type = ['lost', 'found'].includes(req.query.type) ? req.query.type : '';
  const status = ['open', 'returned'].includes(req.query.status) ? req.query.status : '';
  const selTags = parseTags([].concat(req.query.tag || []).join(','));

  let sql = 'SELECT i.*, u.username FROM items i JOIN users u ON u.id = i.user_id WHERE 1=1';
  const params = [];
  if (q) {
    sql += ' AND (i.title LIKE ? OR i.description LIKE ? OR i.location LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  if (type) { sql += ' AND i.type = ?'; params.push(type); }
  if (status) { sql += ' AND i.status = ?'; params.push(status); }
  if (selTags.length) {
    // ต้องมี "ทุกแท็ก" ที่เลือก (AND)
    sql += ` AND i.id IN (
      SELECT it.item_id FROM item_tags it JOIN tags t ON t.id = it.tag_id
      WHERE t.name IN (${selTags.map(() => '?').join(',')})
      GROUP BY it.item_id HAVING COUNT(DISTINCT t.id) = ?)`;
    params.push(...selTags, selTags.length);
  }
  sql += ' ORDER BY i.created_at DESC LIMIT 100';

  const items = attachTags(db.prepare(sql).all(...params));
  const allTags = db.prepare(
    `SELECT t.name, COUNT(it.item_id) AS cnt FROM tags t
     JOIN item_tags it ON it.tag_id = t.id GROUP BY t.id ORDER BY cnt DESC, t.name`
  ).all();

  const toggleTag = (tag) => {
    const next = selTags.includes(tag) ? selTags.filter(t => t !== tag) : [...selTags, tag];
    const p = new URLSearchParams();
    if (q) p.set('q', q);
    if (type) p.set('type', type);
    if (status) p.set('status', status);
    next.forEach(t => p.append('tag', t));
    return '/?' + p.toString();
  };

  res.render('index', { items, allTags, q, type, status, selTags, toggleTag });
});

// ---------- สมัคร / เข้าสู่ระบบ ----------
app.get('/register', (req, res) => res.locals.user ? res.redirect('/') : res.render('register'));

app.post('/register', (req, res, next) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const fail = (msg) => { flash(req, 'error', msg); res.redirect('/register'); };

  if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) return fail('ชื่อผู้ใช้ต้องเป็น a-z, 0-9, _ ความยาว 3-30 ตัว');
  if (password.length < 6) return fail('รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร');
  if (password !== req.body.confirm) return fail('รหัสผ่านยืนยันไม่ตรงกัน');

  try {
    const r = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
      .run(username, bcrypt.hashSync(password, 10));
    log(r.lastInsertRowid, 'register', username);
    loginUser(req, r.lastInsertRowid, err => {
      if (err) return next(err);
      flash(req, 'success', 'สมัครสมาชิกสำเร็จ ยินดีต้อนรับ!');
      res.redirect('/');
    });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return fail('ชื่อผู้ใช้นี้ถูกใช้แล้ว');
    next(e);
  }
});

app.get('/login', (req, res) => res.locals.user ? res.redirect('/') : res.render('login'));

app.post('/login', (req, res, next) => {
  const username = String(req.body.username || '').trim();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(String(req.body.password || ''), user.password_hash)) {
    log(null, 'login_failed', username);
    flash(req, 'error', 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
    return res.redirect('/login');
  }
  loginUser(req, user.id, err => {
    if (err) return next(err);
    log(user.id, 'login');
    flash(req, 'success', `ยินดีต้อนรับ ${user.username}`);
    res.redirect(user.role === 'admin' ? '/admin' : '/');
  });
});

app.post('/logout', (req, res) => {
  if (res.locals.user) log(res.locals.user.id, 'logout');
  req.session.destroy(() => res.redirect('/'));
});

// ---------- จัดการรายการ ----------
app.get('/items/new', requireLogin, (req, res) => res.render('item-form', { item: null, action: '/items' }));

app.post('/items', requireLogin, handleUpload, (req, res) => {
  const data = readItemForm(req.body);
  if (!data.title) {
    removeImage(req.file?.filename);
    flash(req, 'error', 'กรุณากรอกชื่อสิ่งของ');
    return res.redirect('/items/new');
  }
  const r = db.prepare(
    `INSERT INTO items (type, title, description, location, event_date, contact, image, user_id)
     VALUES (@type, @title, @description, @location, @event_date, @contact, @image, @user_id)`
  ).run({ ...data, image: req.file?.filename || null, user_id: res.locals.user.id });

  setItemTags(r.lastInsertRowid, parseTags(req.body.tags));
  log(res.locals.user.id, 'item_create', `#${r.lastInsertRowid} ${data.title}`);
  flash(req, 'success', 'บันทึกข้อมูลเรียบร้อยแล้ว');
  res.redirect(`/items/${r.lastInsertRowid}`);
});

app.get('/items/:id', loadItem, (req, res) =>
  res.render('item', { item: req.item, manage: canManage(res.locals.user, req.item) }));

app.get('/items/:id/edit', requireLogin, loadItem, requireOwner, (req, res) =>
  res.render('item-form', { item: req.item, action: `/items/${req.item.id}/edit` }));

app.post('/items/:id/edit', requireLogin, loadItem, requireOwner, handleUpload, (req, res) => {
  const data = readItemForm(req.body);
  if (!data.title) {
    removeImage(req.file?.filename);
    flash(req, 'error', 'กรุณากรอกชื่อสิ่งของ');
    return res.redirect(`/items/${req.item.id}/edit`);
  }
  let image = req.item.image;
  if (req.file) { removeImage(image); image = req.file.filename; }
  else if (req.body.remove_image) { removeImage(image); image = null; }

  db.prepare(
    `UPDATE items SET type=@type, title=@title, description=@description, location=@location,
     event_date=@event_date, contact=@contact, image=@image WHERE id=@id`
  ).run({ ...data, image, id: req.item.id });

  setItemTags(req.item.id, parseTags(req.body.tags));
  cleanupTags();
  log(res.locals.user.id, 'item_update', `#${req.item.id} ${data.title}`);
  flash(req, 'success', 'แก้ไขข้อมูลเรียบร้อยแล้ว');
  res.redirect(`/items/${req.item.id}`);
});

app.post('/items/:id/status', requireLogin, loadItem, requireOwner, (req, res) => {
  const status = req.item.status === 'open' ? 'returned' : 'open';
  db.prepare('UPDATE items SET status = ? WHERE id = ?').run(status, req.item.id);
  log(res.locals.user.id, 'item_status', `#${req.item.id} ${req.item.title} -> ${status}`);
  flash(req, 'success', status === 'returned' ? 'อัปเดตสถานะเป็น "ส่งคืนแล้ว"' : 'เปิดรายการอีกครั้ง');
  res.redirect(safeRedirect(req.body.redirect, `/items/${req.item.id}`));
});

app.post('/items/:id/delete', requireLogin, loadItem, requireOwner, (req, res) => {
  db.prepare('DELETE FROM items WHERE id = ?').run(req.item.id);
  removeImage(req.item.image);
  cleanupTags();
  log(res.locals.user.id, 'item_delete', `#${req.item.id} ${req.item.title}`);
  flash(req, 'success', 'ลบรายการแล้ว');
  res.redirect(safeRedirect(req.body.redirect, '/'));
});

// ---------- แอดมิน ----------
app.use('/admin', requireLogin, requireAdmin);

app.get('/admin', (req, res) => {
  const stats = db.prepare(
    `SELECT COUNT(*) AS total,
            COALESCE(SUM(type = 'lost'), 0) AS lost,
            COALESCE(SUM(type = 'found'), 0) AS found,
            COALESCE(SUM(status = 'returned'), 0) AS returned
     FROM items`
  ).get();
  stats.users = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;

  const users = db.prepare(
    `SELECT u.id, u.username, u.role, u.created_at,
            (SELECT COUNT(*) FROM items WHERE user_id = u.id) AS item_count
     FROM users u ORDER BY u.id`
  ).all();
  const items = db.prepare(
    'SELECT i.*, u.username FROM items i JOIN users u ON u.id = i.user_id ORDER BY i.id DESC LIMIT 200'
  ).all();
  const tags = db.prepare(
    `SELECT t.id, t.name, COUNT(it.item_id) AS cnt FROM tags t
     LEFT JOIN item_tags it ON it.tag_id = t.id GROUP BY t.id ORDER BY cnt DESC, t.name`
  ).all();
  const logs = db.prepare(
    'SELECT l.*, u.username FROM logs l LEFT JOIN users u ON u.id = l.user_id ORDER BY l.id DESC LIMIT 200'
  ).all();

  res.render('admin', { stats, users, items, tags, logs });
});

app.post('/admin/users/:id/role', (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target || target.id === res.locals.user.id) {
    flash(req, 'error', 'ไม่สามารถเปลี่ยนสิทธิ์บัญชีนี้ได้');
    return res.redirect('/admin#users');
  }
  const role = target.role === 'admin' ? 'user' : 'admin';
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, target.id);
  log(res.locals.user.id, 'user_role', `${target.username} -> ${role}`);
  flash(req, 'success', `เปลี่ยนสิทธิ์ ${target.username} เป็น ${role} แล้ว`);
  res.redirect('/admin#users');
});

app.post('/admin/users/:id/delete', (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target || target.id === res.locals.user.id) {
    flash(req, 'error', 'ไม่สามารถลบบัญชีนี้ได้');
    return res.redirect('/admin#users');
  }
  db.prepare('SELECT image FROM items WHERE user_id = ?').all(target.id).forEach(r => removeImage(r.image));
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  cleanupTags();
  log(res.locals.user.id, 'user_delete', target.username);
  flash(req, 'success', `ลบผู้ใช้ ${target.username} แล้ว`);
  res.redirect('/admin#users');
});

app.post('/admin/tags/:id/delete', (req, res) => {
  const tag = db.prepare('SELECT * FROM tags WHERE id = ?').get(req.params.id);
  if (tag) {
    db.prepare('DELETE FROM tags WHERE id = ?').run(tag.id);
    log(res.locals.user.id, 'tag_delete', tag.name);
    flash(req, 'success', `ลบแท็ก #${tag.name} แล้ว`);
  }
  res.redirect('/admin#tags');
});

// ---------- Error ----------
app.use((req, res) => res.status(404).render('error', { message: 'ไม่พบหน้าที่คุณต้องการ' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { message: 'เกิดข้อผิดพลาดภายในระบบ' });
});

app.listen(PORT, () => console.log(`เปิดเว็บได้ที่ http://localhost:${PORT}`));