// index.js — Cashlot backend (Express + SQLite, ESM)

import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";

// ---------- Setup ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// SQLite DB file next to this file
const dbPath = path.join(__dirname, "cashlot.db");
const raw = new sqlite3.Database(dbPath);

// Promisified helpers
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    raw.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this); // has lastID, changes
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    raw.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    raw.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

// ---------- DB bootstrap ----------
await dbRun(`
  CREATE TABLE IF NOT EXISTS users
  ( id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,              -- stores bcrypt hash
    role TEXT DEFAULT "user",
    coins INTEGER DEFAULT 0
  )
`);
await dbRun(`
  CREATE TABLE IF NOT EXISTS offers
  ( id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, type TEXT, payout TEXT )
`);
await dbRun(`
  CREATE TABLE IF NOT EXISTS leaderboard
  ( id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT, earned INTEGER )
`);
await dbRun(`
  CREATE TABLE IF NOT EXISTS payouts
  ( id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT, amount INTEGER, status TEXT )
`);
await dbRun(`
  CREATE TABLE IF NOT EXISTS referrals
  ( id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer TEXT, referee TEXT, bonus INTEGER )
`);

// seed admin (only if missing)
{
  const row = await dbGet("SELECT * FROM users WHERE email=?", ["admin@cashlot.gg"]);
  if (!row) {
    const hash = await bcrypt.hash("admin123", 10);
    await dbRun(
      "INSERT INTO users (email, password, role, coins) VALUES (?,?,?,?)",
      ["admin@cashlot.gg", hash, "admin", 100000]
    );
  }
}

// seed demo data
{
  const row = await dbGet("SELECT COUNT(*) AS c FROM offers");
  if (row?.c === 0) {
    const offers = [
      ["BitLabs Surveys", "Surveys", "op til 2,500 coins"],
      ["AdGate Media", "Offerwall", "op til 10,000 coins"],
      ["CPX Research", "Surveys", "op til 3,000 coins"],
      ["Lootably", "Offerwall", "op til 8,000 coins"],
      ["RevU Apps", "Apps", "op til 15,000 coins"],
    ];
    for (const o of offers) {
      await dbRun("INSERT INTO offers (name,type,payout) VALUES (?,?,?)", o);
    }
  }
  const row2 = await dbGet("SELECT COUNT(*) AS c FROM leaderboard");
  if (row2?.c === 0) {
    const lb = [
      ["@mads", 48250],
      ["@sara", 41190],
      ["@niko", 36210],
      ["@clara", 28560],
      ["@leo", 21050],
    ];
    for (const l of lb) {
      await dbRun("INSERT INTO leaderboard (user, earned) VALUES (?,?)", l);
    }
  }
}

// ---------- CONFIG & auth helpers ----------
const SIGNUP_BONUS_COINS = Number(process.env.SIGNUP_BONUS_COINS || 500);

// very simple tokens: "u-<id>"
function makeToken(userId) {
  return `u-${userId}`;
}
function parseToken(token) {
  if (!token || !token.startsWith("u-")) return null;
  const id = Number(token.slice(2));
  return Number.isFinite(id) ? id : null;
}
function auth(req, res, next) {
  const token =
    req.header("Authorization")?.replace("Bearer ", "") || req.query.token;
  const userId = parseToken(token);
  if (!userId) return res.status(401).json({ error: "unauthorized" });
  req.userId = userId;
  next();
}

// --- tiny user repo ---
const db = {
  user: {
    findByEmail: (email) =>
      dbGet("SELECT * FROM users WHERE email = ?", [email]),
    findById: (id) =>
      dbGet("SELECT id,email,role,coins FROM users WHERE id = ?", [id]),
    create: async ({ email, password_hash, role = "user", balance = 0, referral_code_used = null }) => {
      const r = await dbRun(
        "INSERT INTO users (email, password, role, coins) VALUES (?,?,?,?)",
        [email, password_hash, role, balance]
      );
      return { id: r.lastID, email, role, coins: balance };
    },
    incrementCoins: (id, delta) =>
      dbRun("UPDATE users SET coins = coins + ? WHERE id = ?", [delta, id]),
  },
};

// ---------- Public API (demo) ----------
app.get("/api/offers", async (_req, res) => {
  const rows = await dbAll("SELECT * FROM offers");
  res.json(rows || []);
});
app.get("/api/leaderboard", async (_req, res) => {
  const rows = await dbAll("SELECT user, earned FROM leaderboard ORDER BY earned DESC");
  res.json(rows || []);
});
app.get("/api/payouts", async (_req, res) => {
  const rows = await dbAll("SELECT * FROM payouts ORDER BY id DESC");
  res.json(rows || []);
});
app.get("/api/referrals", async (_req, res) => {
  const rows = await dbAll("SELECT * FROM referrals ORDER BY id DESC");
  res.json(rows || []);
});

// ---------- Auth + user (supports both /auth/* and /api/auth/*) ----------
const signupHandler = async (req, res) => {
  try {
    const { email, password, referralCode } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Missing email or password" });
    if (String(password).length < 6) return res.status(400).json({ error: "Password must be ≥ 6 chars" });

    const existing = await db.user.findByEmail(email);
    if (existing) return res.status(409).json({ error: "Email already in use" });

    const hash = await bcrypt.hash(password, 10);
    const user = await db.user.create({
      email,
      password_hash: hash,
      balance: SIGNUP_BONUS_COINS,
      referral_code_used: referralCode || null,
    });

    const token = makeToken(user.id);
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Signup failed" });
  }
};
const loginHandler = async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Missing email or password" });

    const user = await db.user.findByEmail(email);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password || "");
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = makeToken(user.id);
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed" });
  }
};
const meHandler = async (req, res) => {
  const user = await db.user.findById(req.userId);
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json(user);
};

app.post(["/auth/signup", "/api/auth/signup"], signupHandler);
app.post(["/auth/login", "/api/auth/login"], loginHandler);
app.get(["/me", "/api/me"], auth, meHandler);

// ---------- Payout requests ----------
app.post("/api/payouts/request", auth, async (req, res) => {
  const { method, amount } = req.body || {};
  const amt = Number(amount) || 0;
  if (!method || amt <= 0) return res.status(400).json({ error: "invalid" });
  const r = await dbRun(
    "INSERT INTO payouts (method, amount, status) VALUES (?,?,?)",
    [method, amt, "pending"]
  );
  res.json({ ok: true, id: r.lastID });
});
app.get("/api/payouts/mine", auth, async (_req, res) => {
  const rows = await dbAll(
    "SELECT id,method,amount,status FROM payouts ORDER BY id DESC"
  );
  res.json(rows || []);
});

// ---------- BitLabs postback (TEMP: no signature verify) ----------
app.get("/postback/bitlabs", async (req, res) => {
  const { user_id, amount = 0 } = req.query;
  await dbRun(
    "INSERT INTO payouts (method, amount, status) VALUES (?,?,?)",
    ["bitlabs", Number(amount) || 0, "paid"]
  );
  // Optional credit:
  // if (user_id) await db.user.incrementCoins(Number(user_id), Number(amount)||0);
  res.status(200).send("OK");
});

// ---------- Healthcheck ----------
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// ---------- Start server ----------
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
app.listen(PORT, () => console.log("Cashlot backend on port " + PORT));
