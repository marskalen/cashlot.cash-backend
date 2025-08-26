// routes/auth.js
import { Router } from "express";
import bcrypt from "bcryptjs";

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function genCode(n = 6) {
  return Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join("");
}

export default function createAuthRouter({ db, mailer, jwtSecret, smtpFrom, googleClient, signToken }) {
  const router = Router();

  // --------- REGISTER ----------
  // POST /auth/register { email, password, username? }
  router.post("/register", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const password = String(req.body?.password || "");
      const username = String(req.body?.username || email.split("@")[0]);

      if (!email || !password) return res.status(400).json({ error: "Missing email/password" });

      const existing = await db.get("SELECT id FROM users WHERE email=?", email);
      if (existing) return res.status(409).json({ error: "Email already registered" });

      const hash = await bcrypt.hash(password, 10);
      const result = await db.run(
        "INSERT INTO users (email, password_hash, username, provider, verified) VALUES (?, ?, ?, 'local', 0)",
        email, hash, username
      );
      const userId = result.lastID;

      // Send verification code
      const code = genCode(6);
      const expiresAt = Date.now() + 15 * 60 * 1000; // 15 min
      await db.run(
        "INSERT INTO email_verification_codes (user_id, code, expires_at, used) VALUES (?, ?, ?, 0)",
        userId, code, expiresAt
      );

      await mailer.sendMail({
        from: smtpFrom,
        to: email,
        subject: "Cashlot – bekræft din email",
        text: `Din bekræftelseskode: ${code} (gyldig i 15 minutter).`,
      });

      const user = await db.get(
        "SELECT id,email,username,verified,coins,provider FROM users WHERE id=?",
        userId
      );
      const token = signToken(user);
      return res.json({ token, user });
    } catch (e) {
      console.error("REGISTER error:", e);
      return res.status(500).json({ error: "Server error" });
    }
  });

  // --------- LOGIN ----------
  // POST /auth/login { email, password }
  router.post("/login", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const password = String(req.body?.password || "");
      if (!email || !password) return res.status(400).json({ error: "Missing email/password" });

      const user = await db.get("SELECT * FROM users WHERE email=?", email);
      if (!user || !user.password_hash) return res.status(401).json({ error: "Invalid credentials" });

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: "Invalid credentials" });

      const publicUser = {
        id: user.id,
        email: user.email,
        username: user.username,
        verified: user.verified,
        coins: user.coins,
        provider: user.provider,
      };
      const token = signToken(publicUser);
      return res.json({ token, user: publicUser });
    } catch (e) {
      console.error("LOGIN error:", e);
      return res.status(500).json({ error: "Server error" });
    }
  });

  // --------- REQUEST EMAIL VERIFY ----------
  // POST /auth/request-verify { email }
  router.post("/request-verify", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      if (!email) return res.status(400).json({ error: "Missing email" });

      const user = await db.get("SELECT * FROM users WHERE email=?", email);
      if (!user) return res.json({ ok: true }); // undgå enumeration

      if (user.verified) return res.json({ ok: true });

      const code = genCode(6);
      const expiresAt = Date.now() + 15 * 60 * 1000;
      await db.run(
        "INSERT INTO email_verification_codes (user_id, code, expires_at, used) VALUES (?, ?, ?, 0)",
        user.id, code, expiresAt
      );

      await mailer.sendMail({
        from: smtpFrom,
        to: email,
        subject: "Cashlot – bekræft din email",
        text: `Din bekræftelseskode: ${code} (gyldig i 15 minutter).`,
      });

      return res.json({ ok: true });
    } catch (e) {
      console.error("REQUEST-VERIFY error:", e);
      return res.status(500).json({ error: "Server error" });
    }
  });

  // --------- VERIFY EMAIL ----------
  // POST /auth/verify { email, code }
  router.post("/verify", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const code = String(req.body?.code || "");
      if (!email || !code) return res.status(400).json({ error: "Missing email/code" });

      const user = await db.get("SELECT * FROM users WHERE email=?", email);
      if (!user) return res.status(400).json({ error: "Invalid code" });

      const rec = await db.get(
        "SELECT * FROM email_verification_codes WHERE user_id=? AND code=? ORDER BY id DESC LIMIT 1",
        user.id, code
      );
      if (!rec || rec.used || Date.now() > Number(rec.expires_at)) {
        return res.status(400).json({ error: "Invalid or expired code" });
      }

      await db.run("UPDATE users SET verified=1 WHERE id=?", user.id);
      await db.run("UPDATE email_verification_codes SET used=1 WHERE id=?", rec.id);

      const publicUser = {
        id: user.id,
        email: user.email,
        username: user.username,
        verified: 1,
        coins: user.coins,
        provider: user.provider,
      };
      const token = signToken(publicUser);
      return res.json({ token, user: publicUser });
    } catch (e) {
      console.error("VERIFY error:", e);
      return res.status(500).json({ error: "Server error" });
    }
  });

  // --------- REQUEST RESET ----------
  // POST /auth/request-reset { email }
  router.post("/request-reset", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      if (!email) return res.status(400).json({ error: "Missing email" });

      const user = await db.get("SELECT * FROM users WHERE email=?", email);
      // return ok uanset – undgå user enumeration
      if (user) {
        const code = genCode(6);
        const expiresAt = Date.now() + 15 * 60 * 1000;
        await db.run(
          "INSERT INTO password_reset_codes (user_id, code, expires_at, used) VALUES (?, ?, ?, 0)",
          user.id, code, expiresAt
        );
        await mailer.sendMail({
          from: smtpFrom,
          to: email,
          subject: "Cashlot – nulstil adgangskode",
          text: `Din nulstillingskode: ${code} (gyldig i 15 minutter).`,
        });
      }
      return res.json({ ok: true });
    } catch (e) {
      console.error("REQUEST-RESET error:", e);
      return res.status(500).json({ error: "Server error" });
    }
  });

  // --------- RESET PASSWORD ----------
  // POST /auth/reset { email, code, newPassword }
  router.post("/reset", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const code = String(req.body?.code || "");
      const newPassword = String(req.body?.newPassword || "");
      if (!email || !code || !newPassword) {
        return res.status(400).json({ error: "Missing email/code/newPassword" });
      }

      const user = await db.get("SELECT * FROM users WHERE email=?", email);
      if (!user) return res.status(400).json({ error: "Invalid or expired code" });

      const rec = await db.get(
        "SELECT * FROM password_reset_codes WHERE user_id=? AND code=? ORDER BY id DESC LIMIT 1",
        user.id, code
      );
      if (!rec || rec.used || Date.now() > Number(rec.expires_at)) {
        return res.status(400).json({ error: "Invalid or expired code" });
      }

      const hash = await bcrypt.hash(newPassword, 10);
      await db.run("UPDATE users SET password_hash=? WHERE id=?", hash, user.id);
      await db.run("UPDATE password_reset_codes SET used=1 WHERE id=?", rec.id);

      const publicUser = {
        id: user.id,
        email: user.email,
        username: user.username,
        verified: user.verified,
        coins: user.coins,
        provider: user.provider,
      };
      const token = signToken(publicUser);
      return res.json({ ok: true, token, user: publicUser });
    } catch (e) {
      console.error("RESET error:", e);
      return res.status(500).json({ error: "Server error" });
    }
  });

  // --------- GOOGLE LOGIN ----------
  // POST /auth/google { idToken }
  router.post("/google", async (req, res) => {
    try {
      const idToken = String(req.body?.idToken || "");
      if (!googleClient) return res.status(500).json({ error: "Google not configured" });
      if (!idToken) return res.status(400).json({ error: "Missing idToken" });

      const ticket = await googleClient.verifyIdToken({ idToken, audience: undefined });
      const payload = ticket.getPayload();
      if (!payload?.email) return res.status(400).json({ error: "No email in token" });

      const email = normalizeEmail(payload.email);
      let user = await db.get("SELECT * FROM users WHERE email=?", email);

      if (!user) {
        const username = (payload.name || email.split("@")[0]).slice(0, 32);
        const result = await db.run(
          "INSERT INTO users (email, username, provider, verified) VALUES (?, ?, 'google', 1)",
          email, username
        );
        user = await db.get("SELECT * FROM users WHERE id=?", result.lastID);
      } else {
        // Markér som verificeret og sæt provider hvis nødvendigt
        if (!user.verified || user.provider !== "google") {
          await db.run("UPDATE users SET verified=1, provider='google' WHERE id=?", user.id);
          user = await db.get("SELECT * FROM users WHERE id=?", user.id);
        }
      }

      const publicUser = {
        id: user.id,
        email: user.email,
        username: user.username,
        verified: user.verified,
        coins: user.coins,
        provider: user.provider,
      };
      const token = signToken(publicUser);
      return res.json({ token, user: publicUser });
    } catch (e) {
      console.error("GOOGLE error:", e);
      return res.status(401).json({ error: "Invalid Google token" });
    }
  });

  // --------- OPTIONAL: whoami (kræver Authorization: Bearer <token>) ----------
  router.get("/whoami", (req, res) => {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });
    try {
      const payload = jwtVerify(token, jwtSecret);
      return res.json({ me: payload });
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  });

  return router;
}

/* Small helper so we don't import jsonwebtoken again here */
function jwtVerify(token, secret) {
  const jwt = require("jsonwebtoken");
  return jwt.verify(token, secret);
}
