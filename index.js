import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import sqlite3 from "sqlite3";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// --- DB SETUP ---
sqlite3.verbose();
const db = new sqlite3.Database("./cashlot.db");

// Opret tabel (UNIQUE email) + standardfelter
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    username TEXT,
    coins INTEGER DEFAULT 500,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// --- HEALTH ---
app.get("/health", (_req, res) => res.json({ ok: true }));

// --- AUTH: REGISTER ---
app.post("/auth/register", (req, res) => {
  try {
    let { email, password, username } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    email = String(email).trim().toLowerCase();
    username = username?.trim() || email.split("@")[0];

    db.get("SELECT id FROM users WHERE email = ?", [email], async (err, row) => {
      if (err) {
        console.error("DB error (check email):", err);
        return res.status(500).json({ error: "Database error" });
      }
      if (row) {
        return res.status(409).json({ error: "Email already in use" });
      }

      const hash = await bcrypt.hash(password, 10);
      db.run(
        "INSERT INTO users (email, password_hash, username, coins) VALUES (?, ?, ?, ?)",
        [email, hash, username, 500],
        function (insertErr) {
          if (insertErr) {
            if (String(insertErr?.message || "").includes("UNIQUE")) {
              return res.status(409).json({ error: "Email already in use" });
            }
            console.error("DB error (insert user):", insertErr);
            return res.status(500).json({ error: "Database error" });
          }
          return res.status(201).json({
            user: { id: this.lastID, email, username, coins: 500 }
          });
        }
      );
    });
  } catch (e) {
    console.error("REGISTER error", e);
    return res.status(500).json({ error: "Unexpected error" });
  }
});

// --- AUTH: LOGIN ---
app.post("/auth/login", (req, res) => {
  let { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  email = String(email).trim().toLowerCase();

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) {
      console.error("DB error (login):", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const { password_hash, ...publicUser } = user;
    return res.json({ user: publicUser });
  });
});

// --- ME (valgfrit “public” uden token til demo) ---
app.get("/me/:email", (req, res) => {
  const email = String(req.params.email || "").trim().toLowerCase();
  if (!email) return res.status(400).json({ error: "Missing email" });

  db.get("SELECT id, email, username, coins, created_at FROM users WHERE email = ?", [email], (err, row) => {
    if (err) {
      console.error("DB error (/me):", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (!row) return res.status(404).json({ error: "Not found" });
    return res.json({ user: row });
  });
});

// --- START SERVER ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("Server listening on", PORT);
});
