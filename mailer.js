// mailer.js
import nodemailer from "nodemailer";

const {
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,
  FROM_EMAIL,
} = process.env;

// Hjælp: lav bool korrekt fra env
const secureBool = String(SMTP_SECURE).toLowerCase() === "true";
const portNum = Number(SMTP_PORT) || 587;

// ADVARSEL: 587 bruges normalt med secure=false (STARTTLS)
if (portNum === 587 && secureBool) {
  console.warn("[SMTP] Warning: PORT=587 men SECURE=true. Overvej at sætte SMTP_SECURE=false (STARTTLS).");
}

export const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: portNum,
  secure: secureBool, // true for 465 (SSL), false for 587 (STARTTLS)
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

// 🔎 Verificér SMTP-forbindelse ved opstart
transporter
  .verify()
  .then(() => {
    console.log("[SMTP] OK: connection ready");
  })
  .catch((err) => {
    console.error("[SMTP] FAILED:", err?.message || err);
  });

// Normaliser FROM (format: "Navn <email@domæne>")
function normalizedFrom() {
  const fallback = SMTP_USER || "no-reply@localhost";
  // Hvis FROM_EMAIL ikke har vinkelparanteser, forsøg at pakke den pænt
  if (!FROM_EMAIL) return fallback;
  if (FROM_EMAIL.includes("<") && FROM_EMAIL.includes(">")) return FROM_EMAIL;
  // Fx "Cashlot no-reply@cashlot.cash" -> "Cashlot <no-reply@cashlot.cash>"
  const parts = FROM_EMAIL.trim().split(/\s+/);
  const maybeEmail = parts.pop();
  const name = parts.join(" ") || "Cashlot";
  return `${name} <${maybeEmail}>`;
}

export async function sendMail({ to, subject, html, text }) {
  const info = await transporter.sendMail({
    from: normalizedFrom(),
    to,
    subject,
    text,
    html,
    // replyTo: SMTP_USER, // valgfrit
  });
  console.log("[SMTP] Message queued:", info.messageId, "to:", to);
  return info;
}

// simple templates
export function tplVerification({ link }) {
  return {
    subject: "Verify your Cashlot account",
    html: `
      <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif">
        <h2>Confirm your email</h2>
        <p>Thanks for signing up to Cashlot. Click the button below to verify your email.</p>
        <p><a href="${link}" style="background:#2563eb;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none">Verify email</a></p>
        <p>If it doesn't work, copy this URL:</p>
        <p><a href="${link}">${link}</a></p>
      </div>
    `,
    text: `Verify your email: ${link}`,
  };
}

export function tplReset({ link }) {
  return {
    subject: "Reset your Cashlot password",
    html: `
      <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif">
        <h2>Reset your password</h2>
        <p>If you didn't request this, you can ignore this mail.</p>
        <p><a href="${link}" style="background:#2563eb;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none">Reset password</a></p>
        <p>Or open this URL: <a href="${link}">${link}</a></p>
      </div>
    `,
    text: `Reset your password: ${link}`,
  };
}
