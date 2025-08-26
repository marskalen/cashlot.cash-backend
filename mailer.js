// mailer.js
import nodemailer from "nodemailer";

const host = process.env.SMTP_HOST;
const port = Number(process.env.SMTP_PORT || 587);
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASS;
const from = process.env.SMTP_FROM || "no-reply@cashlot.cash";

let transporter;

export function getTransporter() {
  if (!transporter) {
    if (!host || !user || !pass) {
      console.warn("SMTP not configured – emails will be logged.");
      return null;
    }
    transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
    });
  }
  return transporter;
}

export async function sendMail(to, subject, text, html) {
  const tx = getTransporter();
  if (!tx) {
    console.log("---- DEV EMAIL (no SMTP configured) ----");
    console.log("TO:", to);
    console.log("SUBJECT:", subject);
    console.log("TEXT:", text);
    console.log("----------------------------------------");
    return { dev: true };
  }
  return tx.sendMail({ from, to, subject, text, html: html || `<pre>${text}</pre>` });
}
