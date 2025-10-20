import nodemailer from "nodemailer";

const {
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,
  FROM_EMAIL
} = process.env;

export const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT) || 587,
  secure: String(SMTP_SECURE) === "true",
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

export async function sendMail({ to, subject, html, text }) {
  return transporter.sendMail({
    from: FROM_EMAIL || SMTP_USER,
    to,
    subject,
    text,
    html
  });
}

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
    text: `Verify your email: ${link}`
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
    text: `Reset your password: ${link}`
  };
}
