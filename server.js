/**
 * ระบบตารางงาน / ตารางผู้อำนวยการ / ตารางการใช้รถส่วนกลาง
 * เซิร์ฟเวอร์ Node.js + Express  เก็บข้อมูลเป็นไฟล์ JSON ในโฟลเดอร์ data/
 *
 * รัน:  npm install && npm start      (ค่าเริ่มต้น http://localhost:3000)
 */
"use strict";

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const SECRET_FILE = path.join(DATA_DIR, ".secret");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const CONFIG_FILE = path.join(DATA_DIR, "config.json");
const KINDS = ["team", "director", "fleet", "fleetlog"];
const COOKIE = "sched_token";
const TOKEN_DAYS = 30;

/* ---------------- ไฟล์ / ยูทิลิตี้ ---------------- */
fs.mkdirSync(DATA_DIR, { recursive: true });

function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { return fallback; }
}
function writeJSON(file, obj) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, file);            // เขียนแบบ atomic กันไฟล์พังระหว่างบันทึก
}
function secret() {
  if (!fs.existsSync(SECRET_FILE)) fs.writeFileSync(SECRET_FILE, crypto.randomBytes(32).toString("hex"));
  return fs.readFileSync(SECRET_FILE, "utf8").trim();
}
function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const h = crypto.scryptSync(String(pw), salt, 32).toString("hex");
  return salt + ":" + h;
}
function verifyPassword(pw, stored) {
  if (!stored || stored.indexOf(":") < 0) return false;
  const salt = stored.split(":")[0];
  const a = Buffer.from(hashPassword(pw, salt));
  const b = Buffer.from(stored);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  return body + "." + mac;
}
function verify(token) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, mac] = token.split(".");
  const expect = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  if (mac.length !== expect.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expect))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!p.exp || Date.now() > p.exp) return null;
    return p;
  } catch (e) { return null; }
}
function safeMonth(m) { return /^\d{4}-\d{2}$/.test(String(m || "")) ? m : null; }
function dataFile(kind, month) { return path.join(DATA_DIR, kind + "-" + month + ".json"); }

/* ---------------- ผู้ใช้เริ่มต้น ---------------- */
function loadUsers() { return readJSON(USERS_FILE, null); }
function ensureAdmin(force) {
  let users = loadUsers();
  if (users && !force) return;
  const pw = process.env.ADMIN_PASSWORD || "admin1234";
  users = users || [];
  const i = users.findIndex(u => u.username === "admin");
  const admin = {
    username: "admin",
    name: "ผู้ดูแลระบบ",
    role: "admin",
    password: hashPassword(pw),
    mustChange: true
  };
  if (i >= 0) users[i] = admin; else users.unshift(admin);
  writeJSON(USERS_FILE, users);
  console.log("\n=== สร้าง/รีเซ็ตบัญชีผู้ดูแลระบบแล้ว ===");
  console.log("   ชื่อผู้ใช้: admin");
  console.log("   รหัสผ่าน : " + pw + "   (กรุณาเปลี่ยนทันทีหลังเข้าระบบครั้งแรก)\n");
}
ensureAdmin(process.argv.includes("--reset-admin"));
if (process.argv.includes("--reset-admin")) process.exit(0);

/* ---------------- แอป ---------------- */
const app = express();
app.use(express.json({ limit: "2mb" }));
app.disable("x-powered-by");

function cookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach(part => {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
function currentUser(req) {
  const t = verify(cookies(req)[COOKIE]);
  if (!t) return null;
  const u = (loadUsers() || []).find(x => x.username === t.u);
  if (!u) return null;
  return { username: u.username, name: u.name, role: u.role, mustChange: !!u.mustChange };
}
function requireUser(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "ยังไม่ได้เข้าสู่ระบบ" });
  req.user = u; next();
}
function requireEditor(req, res, next) {
  if (req.user.role === "viewer") return res.status(403).json({ error: "บัญชีนี้ดูได้อย่างเดียว" });
  next();
}
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "ต้องเป็นผู้ดูแลระบบ" });
  next();
}

/* ---------------- เข้า/ออกระบบ ---------------- */
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = (loadUsers() || []).find(x => x.username === String(username || "").trim());
  if (!u || !verifyPassword(password, u.password)) {
    return res.status(401).json({ error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
  }
  const token = sign({ u: u.username, exp: Date.now() + TOKEN_DAYS * 86400000 });
  res.setHeader("Set-Cookie",
    COOKIE + "=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + TOKEN_DAYS * 86400);
  res.json({ ok: true, user: { username: u.username, name: u.name, role: u.role, mustChange: !!u.mustChange } });
});

app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", COOKIE + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/me", requireUser, (req, res) => res.json({ user: req.user }));

app.post("/api/password", requireUser, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!newPassword || String(newPassword).length < 6) {
    return res.status(400).json({ error: "รหัสผ่านใหม่ต้องยาวอย่างน้อย 6 ตัวอักษร" });
  }
  const users = loadUsers() || [];
  const u = users.find(x => x.username === req.user.username);
  if (!u || !verifyPassword(oldPassword, u.password)) {
    return res.status(400).json({ error: "รหัสผ่านเดิมไม่ถูกต้อง" });
  }
  u.password = hashPassword(newPassword);
  u.mustChange = false;
  writeJSON(USERS_FILE, users);
  res.json({ ok: true });
});

/* ---------------- ตั้งค่าหน่วยงาน ---------------- */
app.get("/api/config", requireUser, (req, res) => {
  res.json(readJSON(CONFIG_FILE, null) || {});
});
app.put("/api/config", requireUser, requireEditor, (req, res) => {
  writeJSON(CONFIG_FILE, req.body || {});
  res.json({ ok: true });
});

/* ---------------- ข้อมูลตาราง (รายเดือน) ---------------- */
app.get("/api/data/:kind/:month", requireUser, (req, res) => {
  const { kind } = req.params;
  const month = safeMonth(req.params.month);
  if (!KINDS.includes(kind) || !month) return res.status(400).json({ error: "พารามิเตอร์ไม่ถูกต้อง" });
  res.json(readJSON(dataFile(kind, month), { cells: {} }));
});

app.put("/api/data/:kind/:month", requireUser, requireEditor, (req, res) => {
  const { kind } = req.params;
  const month = safeMonth(req.params.month);
  if (!KINDS.includes(kind) || !month) return res.status(400).json({ error: "พารามิเตอร์ไม่ถูกต้อง" });
  const cells = (req.body && req.body.cells) || {};
  const rec = { cells, updatedAt: new Date().toISOString(), updatedBy: req.user.name || req.user.username };
  writeJSON(dataFile(kind, month), rec);
  res.json({ ok: true, updatedAt: rec.updatedAt, updatedBy: rec.updatedBy });
});

/* สรุปเวลาแก้ไขล่าสุดของทุกส่วน ใช้ให้หน้าเว็บรู้ว่าควรโหลดใหม่ */
app.get("/api/stamp/:month", requireUser, (req, res) => {
  const month = safeMonth(req.params.month);
  if (!month) return res.status(400).json({ error: "เดือนไม่ถูกต้อง" });
  const out = {};
  KINDS.forEach(k => {
    try { out[k] = fs.statSync(dataFile(k, month)).mtimeMs; } catch (e) { out[k] = 0; }
  });
  try { out.config = fs.statSync(CONFIG_FILE).mtimeMs; } catch (e) { out.config = 0; }
  res.json(out);
});

/* ---------------- จัดการผู้ใช้ (เฉพาะผู้ดูแลระบบ) ---------------- */
app.get("/api/users", requireUser, requireAdmin, (req, res) => {
  res.json((loadUsers() || []).map(u => ({ username: u.username, name: u.name, role: u.role })));
});

app.post("/api/users", requireUser, requireAdmin, (req, res) => {
  const { username, name, role, password } = req.body || {};
  const uname = String(username || "").trim();
  if (!/^[a-zA-Z0-9._-]{3,32}$/.test(uname)) {
    return res.status(400).json({ error: "ชื่อผู้ใช้ต้องเป็น a-z 0-9 . _ - ยาว 3-32 ตัว" });
  }
  if (!password || String(password).length < 6) {
    return res.status(400).json({ error: "รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร" });
  }
  const users = loadUsers() || [];
  if (users.some(u => u.username === uname)) return res.status(400).json({ error: "มีชื่อผู้ใช้นี้แล้ว" });
  users.push({
    username: uname,
    name: String(name || uname).trim(),
    role: ["admin", "user", "viewer"].includes(role) ? role : "user",
    password: hashPassword(password),
    mustChange: true
  });
  writeJSON(USERS_FILE, users);
  res.json({ ok: true });
});

app.put("/api/users/:username", requireUser, requireAdmin, (req, res) => {
  const users = loadUsers() || [];
  const u = users.find(x => x.username === req.params.username);
  if (!u) return res.status(404).json({ error: "ไม่พบผู้ใช้" });
  if (req.body.name !== undefined) u.name = String(req.body.name).trim();
  if (req.body.role && ["admin", "user", "viewer"].includes(req.body.role)) u.role = req.body.role;
  if (req.body.password) {
    if (String(req.body.password).length < 6) return res.status(400).json({ error: "รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร" });
    u.password = hashPassword(req.body.password);
    u.mustChange = true;
  }
  if (u.username === "admin" && u.role !== "admin") u.role = "admin";   // กันล็อกตัวเองออก
  writeJSON(USERS_FILE, users);
  res.json({ ok: true });
});

app.delete("/api/users/:username", requireUser, requireAdmin, (req, res) => {
  if (req.params.username === "admin") return res.status(400).json({ error: "ลบบัญชีผู้ดูแลระบบหลักไม่ได้" });
  const users = (loadUsers() || []).filter(u => u.username !== req.params.username);
  writeJSON(USERS_FILE, users);
  res.json({ ok: true });
});

/* ---------------- สำรองข้อมูล ---------------- */
app.get("/api/backup", requireUser, requireAdmin, (req, res) => {
  const out = { exportedAt: new Date().toISOString(), config: readJSON(CONFIG_FILE, {}), data: {} };
  fs.readdirSync(DATA_DIR).forEach(f => {
    const m = f.match(/^(team|director|fleet|fleetlog)-(\d{4}-\d{2})\.json$/);
    if (m) out.data[m[1] + "/" + m[2]] = readJSON(path.join(DATA_DIR, f), null);
  });
  res.setHeader("Content-Disposition",
    'attachment; filename="schedule-backup-' + new Date().toISOString().slice(0, 10) + '.json"');
  res.json(out);
});

/* ---------------- หน้าเว็บ ---------------- */
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

app.get("/", (req, res) => {
  if (!currentUser(req)) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname, "public", "app.html"));
});

app.listen(PORT, () => {
  console.log("ระบบตารางงานพร้อมใช้งานที่  http://localhost:" + PORT);
  console.log("โฟลเดอร์ข้อมูล: " + DATA_DIR + "   (สำรองข้อมูล = คัดลอกโฟลเดอร์นี้)");
});
