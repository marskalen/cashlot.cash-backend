// index.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { OAuth2Client } from "google-auth-library";
import createAuthRouter from "./routes/auth.js";

/* ---------- ENV ---------- */
const {
  PORT = 10000,
  NODE_ENV = "production",

  // CORS: tillad flere origins (kommasepareret)
  FRONTEND_ORIGINS = "https://cashlot.cash,https://www.cashlot.cash,http://localhost:5173",

  // JWT
  JWT_SECRET = "dev_secret_change_me",

  // SMTP (kræves i prod for at maile rigtige koder)
  SMTP_HOST,
  SMTP_PORT = "587",
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM = "no-reply@cashlot.cash",

  // Google Sign-In (valgfri)
  GOOGLE_CLIENT_ID,

  // Offerwalls
  BITLABS_S2S_KEY,
} = process.env;

/* ---------- App ---------- */
const app = express();

/* ---------- CORS (robust) ---------- */
const ORIGIN_LIST = FRONTEND_ORIGINS.split(",").map(s => s.trim()).filter(Boolean);
function originOk(origin) {
  if (!origin) return true; // curl/mobile apps
  return ORIGIN_LIST.some(allow => {
    if (allow.startsWith("regex:")) {
      const re = new RegExp(allow.slice(6));
      return re.test(origin);
    }
    return allow === origin;
  });
}
app.use(cors({
  origin: (origin, cb) => originOk(origin) ? cb(null, true) : cb(new Error("CORS: origin not allowed")),
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));
app.options("*", cors());

/* ---------- JSON ---------- */
app.use(express.json());

/* ---------- Health ---------- */
app.get("/health", (_req, res) =>
  res.json({
    ok: true,
    env: NODE_ENV,
    corsOrigins: ORIGIN_LIST,
  })
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
  // Dev fallback: logger mails i konsollen (sender IKKE rigtigt)
  return {
    sendMail: async (opts) => {
      console.log("---- DEV EMAIL (NOT SENT) ----", opts);
      return { messageId: "dev" };
    },
  };
}
const mailer = makeTransport();

/* (valgfri) debug endpoint til at teste SMTP */
app.post("/debug/send-email", async (req, res) => {
  try {
    const to = String(req.body?.to || "businessmarskalen@gmail.com");
    const info = await mailer.sendMail({
      from: SMTP_FROM,
      to,
      subject: "Cashlot test",
      text: "Hvis du ser denne mail, virker SMTP! 🎉",
    });
    res.json({ ok: true, messageId: info.messageId || "n/a" });
  } catch (e) {
    console.error("debug email err", e);
    res.status(500).json({ error: String(e?.message || e) });
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

/* ---------- AUTH (vigtig: kræver den FULDE routes/auth.js) ---------- */
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
app.use("/auth", createAuthRouter({
  db, mailer, smtpFrom: SMTP_FROM, signToken, googleClient
}));

/* (valgfri) Debug: list mounted routes */
app.get("/__routes", (req, res) => {
  const stack = (app._router?.stack || []).map(l => {
    if (l.route) return { path: l.route.path, methods: l.route.methods };
    if (l.name === "router" && l.regexp) return { router: true, mountedAt: l.regexp.toString() };
    return null;
  }).filter(Boolean);
  res.json({ routes: stack });
});

/* ---------- BitLabs S2S callback ---------- */
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

/* ---------- Me (beskyttet) ---------- */
app.get("/me", authMiddleware, async (req, res) => {
  const u = await db.get(
    "SELECT id,email,username,verified,coins,provider FROM users WHERE id=?",
    req.user.uid
  );
  return res.json({ user: u });
});

/* ---------- 404 fallback (JSON) ---------- */
app.use((req, res) => res.status(404).json({ error: "Not found", path: req.path }));

/* ---------- Start ---------- */
app.listen(PORT, () => {
  console.log(`Cashlot backend on :${PORT}`);
  console.log("[CORS] Allowed origins:", ORIGIN_LIST);
});
