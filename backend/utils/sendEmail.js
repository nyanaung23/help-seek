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
      connectionTimeout: 15000, // 15 seconds to establish connection
      socketTimeout: 30000, // 30 seconds for socket operations
      greetingTimeout: 10000, // 10 seconds for SMTP greeting
      tls: {
        // Allow self-signed certificates - many SMTP services use them
        // Set SMTP_REJECT_UNAUTHORIZED=true to enforce strict certificate validation
        rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED === "true",
      },
      // Additional options for better compatibility
      pool: true, // Use connection pooling
      maxConnections: 1,
      maxMessages: 3,
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
      host: host,
      port: port,
      user: user ? "***" : "NOT SET",
    });
    console.warn("[mail] WARNING: SMTP verification failed, but transporter will still attempt to send emails. Check your SMTP configuration.");
  });
} else if (!isSmtpConfigured) {
  console.error("[mail] ERROR: SMTP is not configured. Email sending will fail.");
  console.error("[mail] Required environment variables:");
  console.error("[mail]   - SMTP_HOST (e.g., smtp.gmail.com, smtp.railway.app)");
  console.error("[mail]   - SMTP_PORT (e.g., 587 for TLS, 465 for SSL)");
  console.error("[mail]   - SMTP_USER (your SMTP username/email)");
  console.error("[mail]   - SMTP_PASS (your SMTP password or app password)");
  console.error("[mail] Optional: EMAIL_FROM (defaults to SMTP_USER), SMTP_REJECT_UNAUTHORIZED (default: false)");
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
    // Enhanced error logging for production debugging
    const errorDetails = {
      to,
      subject,
      error: error.message,
      code: error.code,
      command: error.command,
      response: error.response,
      responseCode: error.responseCode,
      host: host || "NOT SET",
      port: port || "NOT SET",
      user: user ? "***" : "NOT SET",
      configured: isSmtpConfigured,
    };
    
    console.error("[mail] sendEmail error:", errorDetails);
    
    // Provide more helpful error messages
    if (!isSmtpConfigured) {
      const configError = new Error("SMTP is not configured. Please set SMTP_HOST, SMTP_USER, and SMTP_PASS environment variables in your deployment platform.");
      configError.code = "SMTP_NOT_CONFIGURED";
      throw configError;
    }
    
    if (error.code === "ECONNREFUSED" || error.code === "ETIMEDOUT") {
      const connError = new Error(`Failed to connect to SMTP server at ${host}:${port}. Check your SMTP_HOST and SMTP_PORT settings.`);
      connError.code = error.code;
      throw connError;
    }
    
    if (error.responseCode === 535 || error.message?.includes("authentication")) {
      const authError = new Error("SMTP authentication failed. Check your SMTP_USER and SMTP_PASS credentials.");
      authError.code = "SMTP_AUTH_FAILED";
      throw authError;
    }
    
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