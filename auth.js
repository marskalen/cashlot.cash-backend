// routes/auth.js
import { Router } from "express";

const router = Router();

// Minimal test-login
router.post("/login", (req, res) => {
  res.json({ ok: true, route: "/auth/login", body: req.body || null });
});

// Minimal test-reset-request
router.post("/request-reset", (req, res) => {
  const email = req.body?.email || null;
  res.json({ ok: true, route: "/auth/request-reset", email });
});

export default router;
