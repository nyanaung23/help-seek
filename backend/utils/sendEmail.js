import nodemailer from "nodemailer";
import { renderVerificationEmail, renderSignupEmail, renderForgotEmail, renderMessageEmail } from "./emails.js";

//Config from .env
const host = process.env.SMTP_HOST;
const port = Number(process.env.SMTP_PORT || "587");
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASS;
const fromDefault = process.env.EMAIL_FROM || (user ? `Help N Seek <${user}>` : "helpnseek@gmail.com");

// Validate SMTP configuration
function validateSmtpConfig() {
  if (!host) {
    console.error("[mail] ERROR: SMTP_HOST is not set in environment variables");
    return false;
  }
  if (!user || !pass) {
    console.error("[mail] ERROR: SMTP_USER and SMTP_PASS must be set in environment variables");
    return false;
  }
  return true;
}

const isSmtpConfigured = validateSmtpConfig();

// Reuseable transporter - only create if properly configured
export const transporter = isSmtpConfigured
  ? nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
      connectionTimeout: 10000, // 10 seconds to establish connection
      socketTimeout: 30000, // 30 seconds for socket operations
      greetingTimeout: 10000, // 10 seconds for SMTP greeting
      tls: {
        rejectUnauthorized: process.env.NODE_ENV === "production", // Only reject in production
      },
    })
  : null;

// Verify connection configuration - log in all environments
console.log("[mail] transporter status:", { 
  host: host || "NOT SET", 
  port, 
  user: user ? "****" : "NOT SET",
  configured: isSmtpConfigured,
  from: fromDefault,
  environment: process.env.NODE_ENV || "development"
});

// Verify transporter connection on startup (only when configured and not explicitly disabled)
if (isSmtpConfigured && transporter && process.env.VERIFY_SMTP_ON_STARTUP !== "false") {
  transporter.verify().then(() => {
    console.log("[mail] SMTP connection verified successfully");
  }).catch((err) => {
    console.error("[mail] SMTP connection verification failed:", {
      message: err.message,
      code: err.code,
      command: err.command,
      response: err.response,
      responseCode: err.responseCode,
    });
  });
} else if (!isSmtpConfigured) {
  console.warn("[mail] WARNING: SMTP is not configured. Email sending will fail. Please set SMTP_HOST, SMTP_USER, and SMTP_PASS environment variables.");
}

// Helper function to add timeout to promises
function withTimeout(promise, timeoutMs = 30000) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Email sending timed out after ${timeoutMs}ms`)), timeoutMs)
    ),
  ]);
}

// Send email
export async function sendEmail({ to, subject, html, text, replyTo }) {
  if (!to || !subject || !html) {
    throw new Error("sendEmail: 'to', 'subject', and 'html' are required");
  }

  if (!isSmtpConfigured || !transporter) {
    const error = new Error("SMTP is not configured. Please set SMTP_HOST, SMTP_USER, and SMTP_PASS environment variables.");
    console.error("[mail] sendEmail failed:", error.message);
    throw error;
  }

  const timeoutMs = Number(process.env.SMTP_TIMEOUT || "30000"); // Default 30 seconds

  try {
    const sendPromise = transporter.sendMail({
      from: fromDefault,
      to,
      subject,
      html,
      text,
      replyTo,
    });

    const info = await withTimeout(sendPromise, timeoutMs);

    // Log in all environments with more details
    console.log("[mail] email sent successfully:", {
      to,
      messageId: info.messageId,
      response: info.response,
      accepted: info.accepted,
      rejected: info.rejected,
    });
    return info;
  } catch (error) {
    console.error("[mail] sendEmail error:", {
      to,
      subject,
      error: error.message,
      code: error.code,
      command: error.command,
    });
    throw error;
  }
}

// Send verification email based on different kinds
export async function sendVerificationEmail(kind, { to, name = "", code, replyTo }) {
  const { subject, html, text } = renderVerificationEmail({ kind, name, code });
  return sendEmail({ to, subject, html, text, replyTo });
}

// Send signup verification email
export async function sendSignupCode({ to, name = "", code, replyTo }) {
  const { subject, html, text } = renderSignupEmail({ name, code });
  return sendEmail({ to, subject, html, text, replyTo });
}

// Send forgot password verification email
export async function sendForgotCode({ to, name = "", code, replyTo }) {
  const { subject, html, text } = renderForgotEmail({ name, code });
  return sendEmail({ to, subject, html, text, replyTo });
}

export async function sendMessageNotification({ to, recipientName = "", senderName = "", preview = "", threadUrl = "" }) {
  const { subject, html, text } = renderMessageEmail({ recipientName, senderName, preview, threadUrl });
  return sendEmail({ to, subject, html, text });
}