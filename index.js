import "dotenv/config.js";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import Database from "better-sqlite3";
import path from "node:path";
import fs from "node:fs";

import authRoutes from "./routes/auth.js";

const app = express();

/** CORS */
const origins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || origins.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true
  })
);

/** Parsers */
app.use(express.json());
app.use(cookieParser());

/** DB init + migrations */
const dbPath = (process.env.DATABASE_URL || "file:./data.sqlite").replace("file:", "");
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
export const db = new Database(dbPath);

// migrations
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

/** Routes */
app.use("/api", authRoutes);

app.get("/health", (req, res) => res.json({ ok: true }));

/** Start */
const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log(`Cashlot API running on :${port}`);
});
