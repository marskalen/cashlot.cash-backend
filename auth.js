// routes/auth.js
import { Router } from "express";
import bcrypt from "bcryptjs";

/** Helpers */
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function genCode(n = 6) {
  return Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join("");
}

export default function createAuthRouter({ db, mailer, smtpFrom, signToken, googleClient }) {
  const router = Router();

  /** REGISTER */
  router.post("/register", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const password = String(req.body?.password || "");
      const username = String(req.body?.username || email.split("@")[0]);
      if (!email || !password) return res.status(400).json({ error: "Missing email/password" });

      const exists = await db.get("SELECT id FROM users WHERE email=?", email);
      if (exists) return res.status(409).json({ error: "Email already registered" });

      const hash = await bcrypt.hash(password, 10);
      const r = await db.run(
        "INSERT INTO users (email, password_hash, username, provider, verified) VALUES (?, ?, ?, 'local', 0)",
        email, hash, username
      );
      const userId = r.lastID;

      // Send verify code
      const code = genCode(6);
      const expiresAt = Date.now() + 15 * 60 * 1000;
      await db.run(
        "INSERT INTO email_verification_codes (user_id, code, expires_at, used) VALUES (?, ?, ?, 0)",
        userId, code, expiresAt
      );
      await mailer.sendMail({
        from: smtpFrom,
        to: email,
        subject: "Cashlot – bekræft din email",
        text: `Din kode: ${code} (gyldig i 15 min).`,
      });

      const user = await db.get("SELECT id,email,username,verified,coins,provider FROM users WHERE id=?", userId);
      const token = signToken(user);
      res.json({ token, user });
    } catch (e) {
      console.error("REGISTER", e);
      res.status(500).json({ error: "Server error" });
    }
  });

  /** LOGIN */
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
        id: user.id, email: user.email, username: user.username,
        verified: user.verified, coins: user.coins, provider: user.provider,
      };
      const token = signToken(publicUser);
      res.json({ token, user: publicUser });
    } catch (e) {
      console.error("LOGIN", e);
      res.status(500).json({ error: "Server error" });
    }
  });

  /** REQUEST VERIFY CODE (send ny kode) */
  router.post("/request-verify", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      if (!email) return res.status(400).json({ error: "Missing email" });

      const user = await db.get("SELECT * FROM users WHERE email=?", email);
      if (!user || user.verified) return res.json({ ok: true });

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
        text: `Din kode: ${code} (gyldig i 15 min).`,
      });
      res.json({ ok: true });
    } catch (e) {
      console.error("REQUEST-VERIFY", e);
      res.status(500).json({ error: "Server error" });
    }
  });

  /** VERIFY EMAIL (indtast kode) */
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
        id: user.id, email: user.email, username: user.username,
        verified: 1, coins: user.coins, provider: user.provider,
      };
      const token = signToken(publicUser);
      res.json({ token, user: publicUser });
    } catch (e) {
      console.error("VERIFY", e);
      res.status(500).json({ error: "Server error" });
    }
  });

  /** REQUEST RESET (glemt password – send kode) */
  router.post("/request-reset", async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      if (!email) return res.status(400).json({ error: "Missing email" });

      const user = await db.get("SELECT * FROM users WHERE email=?", email);
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
          text: `Din nulstillingskode: ${code} (gyldig i 15 min).`,
        });
      }
      // Samme svar uanset om email findes (for ikke at lække)
      res.json({ ok: true });
    } catch (e) {
      console.error("REQUEST-RESET", e);
      res.status(500).json({ error: "Server error" });
    }
  });

  /** RESET PASSWORD (indtast kode + nyt password) */
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
        id: user.id, email: user.email, username: user.username,
        verified: user.verified, coins: user.coins, provider: user.provider,
      };
      const token = signToken(publicUser);
      res.json({ ok: true, token, user: publicUser });
    } catch (e) {
      console.error("RESET", e);
      res.status(500).json({ error: "Server error" });
    }
  });

  /** GOOGLE SIGN-IN (valgfri; kræver GOOGLE_CLIENT_ID) */
  router.post("/google", async (req, res) => {
    try {
      if (!googleClient) return res.status(500).json({ error: "Google not configured" });
      const idToken = String(req.body?.idToken || "");
      if (!idToken) return res.status(400).json({ error: "Missing idToken" });

      const ticket = await googleClient.verifyIdToken({ idToken, audience: undefined });
      const payload = ticket.getPayload();
      const email = normalizeEmail(payload?.email || "");
      if (!email) return res.status(400).json({ error: "No email in token" });

      let user = await db.get("SELECT * FROM users WHERE email=?", email);
      if (!user) {
        const username = (payload?.name || email.split("@")[0]).slice(0, 32);
        const r = await db.run(
          "INSERT INTO users (email, username, provider, verified) VALUES (?, ?, 'google', 1)",
          email, username
        );
        user = await db.get("SELECT * FROM users WHERE id=?", r.lastID);
      } else if (!user.verified || user.provider !== "google") {
        await db.run("UPDATE users SET verified=1, provider='google' WHERE id=?", user.id);
        user = await db.get("SELECT * FROM users WHERE id=?", user.id);
      }

      const publicUser = {
        id: user.id, email: user.email, username: user.username,
        verified: user.verified, coins: user.coins, provider: user.provider,
      };
      const token = signToken(publicUser);
      res.json({ token, user: publicUser });
    } catch (e) {
      console.error("GOOGLE", e);
      res.status(401).json({ error: "Invalid Google token" });
    }
  });

  return router;
}
