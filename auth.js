// Debug-nøgle fra ENV (sæt fx DEBUG_KEY i Render)
const DEBUG_KEY = process.env.DEBUG_KEY;

// Middleware: kræv key for debug endpoints
function requireDebugKey(req, res, next) {
  if (!DEBUG_KEY) return res.status(403).json({ error: "DEBUG disabled" });
  const key = req.query.key || req.headers["x-debug-key"];
  if (key !== DEBUG_KEY) return res.status(403).json({ error: "Bad debug key" });
  next();
}

// GET /api/debug/smtp?key=...
router.get("/debug/smtp", requireDebugKey, async (_req, res) => {
  try {
    await transporter.verify();
    return res.json({ ok: true, smtp: "ready" });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// POST /api/debug/send-test?key=...
router.post("/debug/send-test", requireDebugKey, async (req, res) => {
  const to = req.body?.to;
  if (!to) return res.status(400).json({ error: "Missing 'to'" });
  try {
    const link = `${APP_URL}/verified`; // simpelt testlink
    const info = await sendMail({
      to,
      subject: "Cashlot testmail",
      html: `<p>Hej! Dette er en test.</p><p><a href="${link}">${link}</a></p>`,
      text: `Hej! Dette er en test. ${link}`,
    });
    return res.json({ ok: true, messageId: info.messageId });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});
