// index.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { OAuth2Client } from "google-auth-library";
import createAuthRouter from "./routes/auth.js";

const {
  PORT = 10000,
  JWT_SECRET = "dev_secret_change_me",
  FRONTEND_ORIGIN = "https://cashlot.cash",
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM = "no-reply@cashlot.cash",
  GOOGLE_CLIENT_ID,
  BITLABS_S2S_KEY,
} = process.env;

const app = express();

/* ---------- CORS ---------- */
app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.options("*", cors());

/* ---------- JSON ---------- */
app.use(express.json());

/* ---------- Health ---------- */
app.get("/health", (_req, res) =>
  res.json({ ok: true, env: process.env.NODE_ENV || "production" })
);

/* ---------- Mailer ---------- */
function makeTransport() {
  if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    return nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT || 587),
      secure: Number(SMTP_PORT || 587) === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
  }
  return {
    sendMail: async (opts) => {
      console.log("---- DEV EMAIL ----", opts);
      return { messageId: "dev" };
    },
  };
}
const mailer = makeTransport();

app.post("/debug/send-email", async (req, res) => {
  try {
    const { to = "businessmarskalen@gmail.com" } = req.body || {};
    await mailer.sendMail({
      from: SMTP_FROM,
      to,
      subject: "Cashlot test",
      text: "If you see this, SMTP works! 🎉",
    });
    res.json({ ok: true });
  } catch (e) {
    console.error("debug email err", e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

/* ---------- DB ---------- */
let db;
async function initDb() {
  db = await open({ filename: "./db.sqlite", driver: sqlite3.Database });
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

/* ---------- Helpers ---------- */
function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}
async function findUserByUid(uid) {
  if (/^\d+$/.test(String(uid))) {
    return await db.get("SELECT * FROM users WHERE id=?", Number(uid));
  }
  return await db.get("SELECT * FROM users WHERE email=?", String(uid).toLowerCase());
}

/* ---------- AUTH ROUTES (MOUNT) ---------- */
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
app.use(
  "/auth",
  createAuthRouter({
    db,
    mailer,
    smtpFrom: SMTP_FROM,
    signToken,
    googleClient,
  })
);

/* ---------- BitLabs callback ---------- */
app.get("/bitlabs/callback", async (req, res) => {
  try {
    const { uid, tx, amount, key } = req.query;
    if (!BITLABS_S2S_KEY) return res.status(500).send("S2S not configured");
    if (key !== BITLABS_S2S_KEY) return res.status(401).send("Unauthorized");
    if (!uid || !tx) return res.status(400).send("Missing uid or tx");

    const existing = await db.get("SELECT id FROM offer_events WHERE txid=?", String(tx));
    if (existing) return res.send("OK");

    const user = await findUserByUid(uid);
    if (!user) return res.status(404).send("User not found");

    const usd = Number(amount || 0);
    const coins = Math.max(1, Math.round(usd * 1000));
    await db.run("UPDATE users SET coins = coins + ? WHERE id=?", coins, user.id);

    const raw = JSON.stringify({ provider: "bitlabs", ...req.query });
    await db.run(
      "INSERT INTO offer_events (provider, txid, uid, amount, coins, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
      "bitlabs", String(tx), String(uid), isNaN(usd) ? null : usd, coins, raw
    );

    return res.send("OK");
  } catch (e) {
    console.error("BitLabs callback error:", e);
    return res.status(500).send("ERR");
  }
});

/* ---------- Me (protected) ---------- */
app.get("/me", authMiddleware, async (req, res) => {
  const u = await db.get(
    "SELECT id,email,username,verified,coins,provider FROM users WHERE id=?",
    req.user.uid
  );
  return res.json({ user: u });
});

/* ---------- 404 fallback ---------- */
app.use((req, res) => res.status(404).json({ error: "Not found", path: req.path }));

/* ---------- Start server ---------- */
app.listen(PORT, () => {
  console.log(`Cashlot backend on :${PORT}`);
});
