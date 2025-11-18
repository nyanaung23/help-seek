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
  
  // AWS SES specific validation
  if (host.includes("amazonaws.com") || host.includes("aws")) {
    if (!host.includes("email-smtp")) {
      console.warn("[mail] WARNING: AWS SES SMTP endpoint should be in format: email-smtp.{region}.amazonaws.com");
      console.warn("[mail] Example: email-smtp.us-east-1.amazonaws.com");
    }
    if (port !== 587 && port !== 465 && port !== 2587 && port !== 2465) {
      console.warn("[mail] WARNING: AWS SES typically uses port 587 (TLS) or 465 (SSL)");
    }
  }
  
  return true;
}

const isSmtpConfigured = validateSmtpConfig();

// Create transporter with improved connection settings for cloud environments
function createTransporter() {
  if (!isSmtpConfigured) return null;

  // AWS SES specific configuration
  const isAwsSes = host.includes("amazonaws.com") || host.includes("email-smtp");
  const isSecurePort = port === 465 || port === 2465;
  const isTlsPort = port === 587 || port === 2587;
  
  const transportOptions = {
    host,
    port,
    secure: isSecurePort, // true for 465/2465 (SSL), false for other ports
    auth: { user, pass },
    // Increased timeouts for cloud environments
    connectionTimeout: 20000, // 20 seconds to establish connection
    socketTimeout: 60000, // 60 seconds for socket operations
    greetingTimeout: 15000, // 15 seconds for SMTP greeting
    // Retry configuration
    pool: false, // Disable pooling for better reliability in cloud environments
    // TLS configuration
    tls: {
      // AWS SES requires proper certificate validation
      // Set SMTP_REJECT_UNAUTHORIZED=false only if you have certificate issues
      rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== "false",
      // Additional TLS options for better compatibility
      minVersion: 'TLSv1.2',
      // AWS SES requires proper servername verification
      servername: isAwsSes ? host : undefined,
    },
    // AWS SES requires STARTTLS on port 587
    requireTLS: isTlsPort || isAwsSes,
    // Debug mode (set SMTP_DEBUG=true to enable)
    debug: process.env.SMTP_DEBUG === "true",
    logger: process.env.SMTP_DEBUG === "true",
  };

  return nodemailer.createTransport(transportOptions);
}

export const transporter = createTransporter();

// Verify connection configuration - log in all environments
const isAwsSesHost = host?.includes("amazonaws.com") || host?.includes("email-smtp");
console.log("[mail] transporter status:", { 
  host: host || "NOT SET", 
  port, 
  user: user ? "****" : "NOT SET",
  configured: isSmtpConfigured,
  from: fromDefault,
  environment: process.env.NODE_ENV || "development",
  isAwsSes: isAwsSesHost,
  ...(isAwsSesHost ? {
    awsSesNote: "Ensure SMTP_HOST is region-specific (e.g., email-smtp.us-east-1.amazonaws.com)",
    awsSesCredentialsNote: "Use SMTP credentials from AWS SES Console, not AWS Access Keys"
  } : {})
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

// Helper function to retry email sending with exponential backoff
async function retryWithBackoff(fn, maxRetries = 2, initialDelay = 1000) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      // Don't retry on authentication errors or configuration errors
      if (error.code === "SMTP_NOT_CONFIGURED" || 
          error.code === "SMTP_AUTH_FAILED" ||
          error.responseCode === 535) {
        throw error;
      }
      
      // Only retry on connection/timeout errors
      if (attempt < maxRetries && 
          (error.code === "ETIMEDOUT" || 
           error.code === "ECONNREFUSED" || 
           error.code === "ESOCKET" ||
           error.message?.includes("timeout"))) {
        const delay = initialDelay * Math.pow(2, attempt);
        console.warn(`[mail] Retry attempt ${attempt + 1}/${maxRetries} after ${delay}ms:`, error.message);
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
  throw lastError;
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

  const timeoutMs = Number(process.env.SMTP_TIMEOUT || "60000"); // Default 60 seconds for cloud environments

  try {
    // Use retry logic for connection issues
    const info = await retryWithBackoff(async () => {
      const sendPromise = transporter.sendMail({
        from: fromDefault,
        to,
        subject,
        html,
        text,
        replyTo,
      });
      return await withTimeout(sendPromise, timeoutMs);
    }, 2, 2000); // 2 retries with 2s initial delay

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
    
    if (error.code === "ECONNREFUSED" || error.code === "ETIMEDOUT" || error.code === "ESOCKET") {
      let errorMessage = `Failed to connect to SMTP server at ${host}:${port}. `;
      
      // Provide specific guidance based on the host
      if (host?.includes("gmail.com")) {
        errorMessage += "\n\nGmail SMTP troubleshooting:\n";
        errorMessage += "1. Ensure you're using an App Password (not your regular Gmail password)\n";
        errorMessage += "2. Enable 'Less secure app access' or use OAuth2\n";
        errorMessage += "3. Your cloud provider may be blocking outbound SMTP connections\n";
        errorMessage += "4. Consider using a cloud-friendly email service (SendGrid, Mailgun, etc.)\n";
        errorMessage += "5. Try port 465 (SSL) instead of 587 (TLS) if your provider allows it";
      } else if (host?.includes("amazonaws.com") || host?.includes("email-smtp")) {
        errorMessage += "\n\nAWS SES SMTP troubleshooting:\n";
        errorMessage += "1. Verify SMTP_HOST is region-specific: email-smtp.{region}.amazonaws.com\n";
        errorMessage += "   Example: email-smtp.us-east-1.amazonaws.com\n";
        errorMessage += "2. Ensure you're using SMTP credentials (NOT AWS Access Keys)\n";
        errorMessage += "   - Create SMTP credentials in AWS SES Console > SMTP Settings\n";
        errorMessage += "   - Use the generated SMTP username and password\n";
        errorMessage += "3. Verify the sender email address in AWS SES (must be verified)\n";
        errorMessage += "4. Check if SES is in sandbox mode (can only send to verified emails)\n";
        errorMessage += "5. Use port 587 (TLS/STARTTLS) - recommended for AWS SES\n";
        errorMessage += "   Or port 465 (SSL) if your setup requires it\n";
        errorMessage += "6. Verify the AWS region matches your SES region\n";
        errorMessage += "7. Check AWS SES sending limits and quotas";
      } else {
        errorMessage += "\n\nPossible solutions:\n";
        errorMessage += "1. Check if your deployment platform allows outbound SMTP connections\n";
        errorMessage += "2. Verify SMTP_HOST and SMTP_PORT are correct\n";
        errorMessage += "3. Try a different port (587 for TLS, 465 for SSL)\n";
        errorMessage += "4. Check firewall/network restrictions";
      }
      
      const connError = new Error(errorMessage);
      connError.code = error.code;
      throw connError;
    }
    
    if (error.responseCode === 535 || error.message?.includes("authentication") || error.message?.includes("Invalid login")) {
      let authErrorMessage = "SMTP authentication failed. Check your SMTP_USER and SMTP_PASS credentials.\n";
      
      // AWS SES specific auth error guidance
      if (host?.includes("amazonaws.com") || host?.includes("email-smtp")) {
        authErrorMessage += "\nAWS SES authentication troubleshooting:\n";
        authErrorMessage += "1. Ensure you're using SMTP credentials from AWS SES Console (NOT AWS Access Keys)\n";
        authErrorMessage += "   - Go to AWS SES Console > SMTP Settings > Create SMTP Credentials\n";
        authErrorMessage += "   - Use the generated SMTP Username and Password\n";
        authErrorMessage += "2. Verify the SMTP username format is correct\n";
        authErrorMessage += "3. Check if your IAM user has the 'AmazonSESFullAccess' policy\n";
        authErrorMessage += "4. Ensure the credentials are for the correct AWS region";
      }
      
      const authError = new Error(authErrorMessage);
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