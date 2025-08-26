import "dotenv/config";
import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { OAuth2Client } from "google-auth-library";

const {
  PORT = 10000,
  JWT_SECRET = "dev_secret_change_me",
  FRONTEND_ORIGIN = "https://cashlot.cash",
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM = "no-reply@cashlot.cash",
  GOOGLE_CLIENT_ID
} = process.env;

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: [FRONTEND_ORIGIN, "http://localhost:5173"],
    credentials: false,
  })
);

// ---------------- DB ----------------
let db;
async function initDb() {
  db = await open({
    filename: "./db.sqlite",
    driver: sqlite3.Database,
  });

  await db.exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      username TEXT,
      provider TEXT DEFAULT 'local',
      verified INTEGER DEFAULT 0,
      coins INTEGER DEFAULT 500,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS email_verification_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      code TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS password_reset_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      code TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    -- 🔥 NY TABEL: log for offer postbacks (idempotens)
    CREATE TABLE IF NOT EXISTS offer_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      txid TEXT UNIQUE NOT NULL,
      uid TEXT NOT NULL,
      amount REAL,
      coins INTEGER NOT NULL,
      raw_json TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);
}
await initDb();

// --------------- Email ---------------
function makeTransport() {
  if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    return nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT || 587),
      secure: Number(SMTP_PORT || 587) === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
  }
  // Dev fallback → logger emails i console
  return {
    sendMail: async (opts) => {
      console.log("---- DEV EMAIL (no SMTP configured) ----");
      console.log("TO:", opts.to);
      console.log("SUBJECT:", opts.subject);
      console.log("TEXT:", opts.text);
      console.log("----------------------------------------");
      return { messageId: "dev" };
    },
  };
}
const mailer = makeTransport();

// -------------- Helpers --------------
function genCode(n = 6) {
  return Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join("");
}
function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// 🔎 NY HELPER: find bruger via uid (id eller email)
async function findUserByUid(uid) {
  if (/^\d+$/.test(String(uid))) {
    const u = await db.get("SELECT * FROM users WHERE id = ?", Number(uid));
    if (u) return u;
  }
  const u = await db.get("SELECT * FROM users WHERE email = ?", String(uid).toLowerCase());
  return u || null;
}

// --------------- Routes ---------------
app.get("/health", (_req, res) => res.json({ ok: true }));

// Register
app.post("/auth/register", async (req, res) => {
  const { email, password, username } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email & password required" });

  const existing = await db.get("SELECT id FROM users WHERE email = ?", email.toLowerCase());
  if (existing) return res.status(409).json({ error: "Email already in use" });

  const password_hash = await bcrypt.hash(password, 10);
  const result = await db.run(
    "INSERT INTO users (email, password_hash, username, verified) VALUES (?, ?, ?, 0)",
    email.toLowerCase(),
    password_hash,
    username || null
  );
  const userId = result.lastID;

  // send email code
  const code = genCode(6);
  const expiresAt = Date.now() + 1000 * 60 * 15; // 15 min
  await db.run(
    "INSERT INTO email_verification_codes (user_id, code, expires_at) VALUES (?, ?, ?)",
    userId,
    code,
    expiresAt
  );
  await mailer.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: "Verify your Cashlot email",
    text: `Your verification code is: ${code} (valid for 15 minutes).`,
  });

  const user = await db.get(
    "SELECT id,email,username,verified,coins,provider FROM users WHERE id = ?",
    userId
  );
  return res.json({ user });
});

// Verify email
app.post("/auth/verify-email", async (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: "Email & code required" });

  const user = await db.get("SELECT id, verified FROM users WHERE email = ?", email.toLowerCase());
  if (!user) return res.status(404).json({ error: "User not found" });
  if (user.verified) {
    const token = signToken({ id: user.id, email });
    const safe = await db.get("SELECT id,email,username,verified,coins,provider FROM users WHERE id = ?", user.id);
    return res.json({ token, user: safe, alreadyVerified: true });
  }

  const row = await db.get(
    "SELECT * FROM email_verification_codes WHERE user_id=? AND code=? AND used=0 ORDER BY id DESC LIMIT 1",
    user.id,
    String(code)
  );
  if (!row) return res.status(400).json({ error: "Invalid code" });
  if (Date.now() > row.expires_at) return res.status(400).json({ error: "Code expired" });

  await db.run("UPDATE users SET verified=1 WHERE id=?", user.id);
  await db.run("UPDATE email_verification_codes SET used=1 WHERE id=?", row.id);

  const token = signToken({ id: user.id, email });
  const safe = await db.get("SELECT id,email,username,verified,coins,provider FROM users WHERE id = ?", user.id);
  return res.json({ token, user: safe });
});

// Login (requires verified)
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email & password required" });

  const user = await db.get("SELECT * FROM users WHERE email = ?", email.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  if (user.provider !== "local") return res.status(400).json({ error: "Use Google login for this account" });

  const ok = await bcrypt.compare(password, user.password_hash || "");
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });
  if (!user.verified) return res.status(403).json({ error: "Email not verified" });

  const token = signToken(user);
  const safe = {
    id: user.id,
    email: user.email,
    username: user.username,
    verified: user.verified,
    coins: user.coins,
    provider: user.provider,
  };
  return res.json({ token, user: safe });
});

// Google login
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
app.post("/auth/google", async (req, res) => {
  const { id_token } = req.body || {};
  if (!id_token) return res.status(400).json({ error: "Missing id_token" });
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = (payload.email || "").toLowerCase();
    const username = payload.name || null;

    let user = await db.get("SELECT * FROM users WHERE email=?", email);
    if (!user) {
      const result = await db.run(
        "INSERT INTO users (email, username, provider, verified, coins) VALUES (?, ?, 'google', 1, 500)",
        email,
        username
      );
      user = await db.get("SELECT * FROM users WHERE id=?", result.lastID);
    }
    const token = signToken(user);
    const safe = {
      id: user.id,
      email: user.email,
      username: user.username,
      verified: user.verified,
      coins: user.coins,
      provider: user.provider,
    };
    return res.json({ token, user: safe });
  } catch (e) {
    console.error(e);
    return res.status(401).json({ error: "Invalid Google token" });
  }
});

// Forgot password: request code
app.post("/auth/request-password-reset", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "Email required" });
  const user = await db.get(
    "SELECT id FROM users WHERE email=? AND provider='local'",
    email.toLowerCase()
  );
  if (!user) return res.json({ ok: true }); // silent (ikke leak)
  const code = genCode(6);
  const expiresAt = Date.now() + 1000 * 60 * 15;
  await db.run(
    "INSERT INTO password_reset_codes (user_id, code, expires_at) VALUES (?, ?, ?)",
    user.id,
    code,
    expiresAt
  );
  await mailer.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: "Cashlot password reset",
    text: `Your password reset code is: ${code} (valid for 15 minutes).`,
  });
  return res.json({ ok: true });
});

// Reset password with code
app.post("/auth/reset-password", async (req, res) => {
  const { email, code, new_password } = req.body || {};
  if (!email || !code || !new_password)
    return res.status(400).json({ error: "Missing fields" });
  const user = await db.get(
    "SELECT * FROM users WHERE email=?",
    email.toLowerCase()
  );
  if (!user || user.provider !== "local")
    return res.status(400).json({ error: "Invalid account" });

  const row = await db.get(
    "SELECT * FROM password_reset_codes WHERE user_id=? AND code=? AND used=0 ORDER BY id DESC LIMIT 1",
    user.id,
    String(code)
  );
  if (!row) return res.status(400).json({ error: "Invalid code" });
  if (Date.now() > row.expires_at)
    return res.status(400).json({ error: "Code expired" });

  const hash = await bcrypt.hash(new_password, 10);
  await db.run("UPDATE users SET password_hash=? WHERE id=?", hash, user.id);
  await db.run("UPDATE password_reset_codes SET used=1 WHERE id=?", row.id);
  return res.json({ ok: true });
});

// ------------- BitLabs S2S callback -------------
app.get("/bitlabs/callback", async (req, res) => {
  try {
    const { uid, tx, amount, key } = req.query;

    if (!process.env.BITLABS_S2S_KEY) return res.status(500).send("S2S not configured");
    if (!key || key !== process.env.BITLABS_S2S_KEY) return res.status(401).send("Unauthorized");
    if (!uid || !tx) return res.status(400).send("Missing uid or tx");

    // Idempotens
    const existing = await db.get("SELECT id FROM offer_events WHERE txid = ?", String(tx));
    if (existing) return res.send("OK");

    // Find bruger
    const user = await findUserByUid(uid);
    if (!user) return res.status(404).send("User not found");

    // $1 => 1000 coins
    const usd = Number(amount || 0);
    const coins = Math.max(1, Math.round(usd * 1000));

    await db.run("UPDATE users SET coins = coins + ? WHERE id = ?", coins, user.id);

    const raw = JSON.stringify({ provider: "bitlabs", ...req.query });
    await db.run(
      "INSERT INTO offer_events (provider, txid, uid, amount, coins, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
      "bitlabs",
      String(tx),
      String(uid),
      isNaN(usd) ? null : usd,
      coins,
      raw
    );

    return res.send("OK");
  } catch (e) {
    console.error("BitLabs callback error:", e);
    return res.status(500).send("ERR");
  }
});

// ------------- Protected example -------------
app.get("/me", authMiddleware, async (req, res) => {
  const u = await db.get(
    "SELECT id,email,username,verified,coins,provider FROM users WHERE id=?",
    req.user.uid
  );
  return res.json({ user: u });
});

app.listen(PORT, () => {
  console.log(`Cashlot backend on :${PORT}`);
});
