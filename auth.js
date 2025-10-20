// routes/auth.js
import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { db } from "../index.js";
import { transporter, sendMail, tplVerification, tplReset } from "../mailer.js";

const router = Router();

const APP_URL = process.env.APP_URL || "http://localhost:5173";
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

/* =========================
   Debug key + middleware
   ========================= */
const DEBUG_KEY = process.env.DEBUG_KEY;

function requireDebugKey(req, res, next) {
  if (!DEBUG_KEY) return res.status(403).json({ error: "DEBUG disabled" });
  const key = req.query.key || req.headers["x-debug-key"];
  if (key !== DEBUG_KEY) return res.status(403).json({ error: "Bad debug key" });
  next();
}

// helpers
const nowISO = () => new Date().toISOString();
const addHoursISO = (h) => new Date(Date.now() + h * 3600 * 1000).toISOString();
const genToken = () => crypto.randomBytes(32).toString("hex");

// cookies
const cookieOpts = {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
  path: "/",
  maxAge: 60 * 60 * 24 * 30
};

/* =========================
   AUTH ROUTES
   ========================= */

// REGISTER
router.post("/auth/register", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing email or password" });

  const lower = String(email).toLowerCase();
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(lower);
  if (existing) return res.status(409).json({ error: "Email already exists" });

  const hash = bcrypt.hashSync(password, 10);
  const info = db
    .prepare("INSERT INTO users (email, password_hash, is_verified, created_at, updated_at) VALUES (?,?,?,?,?)")
    .run(lower, hash, 0, nowISO(), nowISO());

  const token = genToken();
  db.prepare(
    "INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?,?,?)"
  ).run(info.lastInsertRowid, token, addHoursISO(24));

  const link = `${APP_URL}/verify?token=${token}`;
  const tpl = tplVerification({ link });
  sendMail({ to: lower, subject: tpl.subject, html: tpl.html, text: tpl.text }).catch(console.error);

  return res.json({ ok: true, message: "Account created. Check your email to verify." });
});

// VERIFY
router.get("/auth/verify", (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: "Missing token" });

  const row = db.prepare("SELECT * FROM email_verification_tokens WHERE token = ?").get(token);
  if (!row) return res.status(400).json({ error: "Invalid token" });
  if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).json({ error: "Token expired" });

  db.prepare("UPDATE users SET is_verified = 1, updated_at = ? WHERE id = ?").run(nowISO(), row.user_id);
  db.prepare("DELETE FROM email_verification_tokens WHERE id = ?").run(row.id);

  return res.redirect(`${APP_URL}/verified`);
});

// LOGIN
router.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const lower = String(email || "").toLowerCase();
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(lower);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  if (!bcrypt.compareSync(password || "", user.password_hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (!user.is_verified) return res.status(403).json({ error: "Email not verified" });

  const token = jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
  res.cookie("cashlot_token", token, cookieOpts);
  return res.json({ ok: true });
});

// LOGOUT
router.post("/auth/logout", (req, res) => {
  res.clearCookie("cashlot_token", { path: "/" });
  return res.json({ ok: true });
});

// ME
router.get("/auth/me", (req, res) => {
  const token = req.cookies?.cashlot_token;
  if (!token) return res.status(401).json({ error: "No session" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare("SELECT id, email, is_verified, created_at FROM users WHERE id = ?").get(payload.uid);
    if (!user) return res.status(401).json({ error: "Invalid session" });
    return res.json({ ok: true, user });
  } catch {
    return res.status(401).json({ error: "Invalid session" });
  }
});

// FORGOT (always 200)
router.post("/auth/forgot", (req, res) => {
  const { email } = req.body || {};
  const lower = String(email || "").toLowerCase();
  const user = db.prepare("SELECT id FROM users WHERE email = ?").get(lower);

  if (user) {
    const token = genToken();
    db.prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?,?,?)")
      .run(user.id, token, addHoursISO(2));
    const link = `${APP_URL}/reset-password?token=${token}`;
    const tpl = tplReset({ link });
    sendMail({ to: lower, subject: tpl.subject, html: tpl.html, text: tpl.text }).catch(console.error);
  }
  return res.json({ ok: true, message: "If the email exists, you will receive a reset link." });
});

// RESET
router.post("/auth/reset", (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: "Missing token or password" });

  const row = db.prepare("SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0").get(token);
  if (!row) return res.status(400).json({ error: "Invalid token" });
  if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).json({ error: "Token expired" });

  const hash = bcrypt.hashSync(password, 10);
  db.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?").run(hash, nowISO(), row.user_id);
  db.prepare("UPDATE password_reset_tokens SET used = 1 WHERE id = ?").run(row.id);

  return res.json({ ok: true, message: "Password updated. You can log in now." });
});

/* =========================
   DEBUG ROUTES (beskyttet)
   ========================= */

// GET /api/debug/smtp?key=...
router.get("/debug/smtp", requireDebugKey, async (_req, res) => {
  try {
    await transporter.verify();
    return res.json({ ok: true, smtp: "ready" });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// POST /api/debug/send-test?key=...
router.post("/debug/send-test", requireDebugKey, async (req, res) => {
  const to = req.body?.to;
  if (!to) return res.status(400).json({ error: "Missing 'to'" });
  try {
    const link = `${APP_URL}/verified`;
    const info = await sendMail({
      to,
      subject: "Cashlot testmail",
      html: `<p>Hej! Dette er en test.</p><p><a href="${link}">${link}</a></p>`,
      text: `Hej! Dette er en test. ${link}`,
    });
    return res.json({ ok: true, messageId: info.messageId });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

export default router;
