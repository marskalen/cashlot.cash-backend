// index.js — Cashlot backend (Express + SQLite)
// ESM because package.json has "type": "module"

import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import path from "path";
import { fileURLToPath } from "url";

// ---------- Setup ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Use SQLite file next to this file
const dbPath = path.join(__dirname, "cashlot.db");
const db = new sqlite3.Database(dbPath);

// ---------- DB bootstrap ----------
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users
    ( id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT "user",
      coins INTEGER DEFAULT 0
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS offers
    ( id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT, type TEXT, payout TEXT )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS leaderboard
    ( id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT, earned INTEGER )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS payouts
    ( id INTEGER PRIMARY KEY AUTOINCREMENT,
      method TEXT, amount INTEGER, status TEXT )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS referrals
    ( id INTEGER PRIMARY KEY AUTOINCREMENT,
      referrer TEXT, referee TEXT, bonus INTEGER )
  `);

  // seed admin
  db.get("SELECT * FROM users WHERE email=?", ["admin@cashlot.gg"], (err, row) => {
    if (!row) {
      db.run(
        "INSERT INTO users (email, password, role, coins) VALUES (?,?,?,?)",
        ["admin@cashlot.gg", "admin123", "admin", 100000]
      );
    }
  });

  // seed offers
  db.get("SELECT COUNT(*) AS c FROM offers", (err, row) => {
    if (row && row.c === 0) {
      const offers = [
        ["BitLabs Surveys", "Surveys", "op til 2,500 coins"],
        ["AdGate Media", "Offerwall", "op til 10,000 coins"],
        ["CPX Research", "Surveys", "op til 3,000 coins"],
        ["Lootably", "Offerwall", "op til 8,000 coins"],
        ["RevU Apps", "Apps", "op til 15,000 coins"],
      ];
      offers.forEach((o) =>
        db.run("INSERT INTO offers (name,type,payout) VALUES (?,?,?)", o)
      );
    }
  });

  // seed leaderboard
  db.get("SELECT COUNT(*) AS c FROM leaderboard", (err, row) => {
    if (row && row.c === 0) {
      const lb = [
        ["@mads", 48250],
        ["@sara", 41190],
        ["@niko", 36210],
        ["@clara", 28560],
        ["@leo", 21050],
      ];
      lb.forEach((l) =>
        db.run("INSERT INTO leaderboard (user, earned) VALUES (?,?)", l)
      );
    }
  });
});

// ---------- CONFIG & auth helpers ----------
const SIGNUP_BONUS_COINS = Number(process.env.SIGNUP_BONUS_COINS || 500); // ~ $0.50 if 1000 coins = $1

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

// ---------- Public API (demo data) ----------
app.get("/api/offers", (req, res) => {
  db.all("SELECT * FROM offers", (err, rows) => res.json(rows || []));
});

app.get("/api/leaderboard", (req, res) => {
  db.all(
    "SELECT user, earned FROM leaderboard ORDER BY earned DESC",
    (err, rows) => res.json(rows || [])
  );
});

app.get("/api/payouts", (req, res) => {
  db.all("SELECT * FROM payouts", (err, rows) => res.json(rows || []));
});

app.get("/api/referrals", (req, res) => {
  db.all("SELECT * FROM referrals", (err, rows) => res.json(rows || []));
});

// ---------- Auth + user ----------
app.post("/api/auth/signup", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "missing fields" });

  db.get("SELECT id FROM users WHERE email = ?", [email], (err, row) => {
    if (row) return res.status(400).json({ error: "user exists" });

    db.run(
      "INSERT INTO users (email, password, role, coins) VALUES (?,?,?,?)",
      [email, password, "user", SIGNUP_BONUS_COINS],
      function (err2) {
        if (err2) return res.status(500).json({ error: "db error" });
        const id = this.lastID;
        const token = makeToken(id);
        res.json({
          token,
          user: { id, email, role: "user", coins: SIGNUP_BONUS_COINS },
        });
      }
    );
  });
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  db.get(
    "SELECT id,email,role,coins FROM users WHERE email=? AND password=?",
    [email, password],
    (err, row) => {
      if (!row) return res.status(401).json({ error: "invalid credentials" });
      const token = makeToken(row.id);
      res.json({ token, user: row });
    }
  );
});

app.get("/api/me", auth, (req, res) => {
  db.get(
    "SELECT id,email,role,coins FROM users WHERE id=?",
    [req.userId],
    (err, row) => {
      if (!row) return res.status(404).json({ error: "not found" });
      res.json(row);
    }
  );
});

// ---------- Payout requests ----------
app.post("/api/payouts/request", auth, (req, res) => {
  const { method, amount } = req.body || {};
  const amt = Number(amount) || 0;
  if (!method || amt <= 0)
    return res.status(400).json({ error: "invalid" });

  db.run(
    "INSERT INTO payouts (method, amount, status) VALUES (?,?,?)",
    [method, amt, "pending"],
    function (err) {
      if (err) return res.status(500).json({ error: "db error" });
      res.json({ ok: true, id: this.lastID });
    }
  );
});

// (Optional) list payout requests (here not filtered by user, adjust if needed)
app.get("/api/payouts/mine", auth, (req, res) => {
  db.all(
    "SELECT id,method,amount,status FROM payouts ORDER BY id DESC",
    (err, rows) => res.json(rows || [])
  );
});

// ---------- BitLabs postback (TEMP: no signature verify) ----------
app.get("/postback/bitlabs", (req, res) => {
  const { user_id, amount = 0, tx_id } = req.query;

  // For now just log as "paid" in payouts.
  db.run(
    "INSERT INTO payouts (method, amount, status) VALUES (?,?,?)",
    ["bitlabs", Number(amount) || 0, "paid"]
  );

  // If you map BitLabs user_id to your user ids:
  // db.run('UPDATE users SET coins = coins + ? WHERE id = ?',
  //   [Number(amount)||0, Number(user_id)||0]);

  res.status(200).send("OK");
});

// ---------- Start server ----------
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
app.listen(PORT, () => console.log("Cashlot backend on port " + PORT));
