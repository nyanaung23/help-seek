import nodemailer from "nodemailer";
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";
import { renderVerificationEmail, renderSignupEmail, renderForgotEmail, renderMessageEmail } from "./emails.js";

//Config from .env
const host = process.env.SMTP_HOST;
const port = Number(process.env.SMTP_PORT || "587");
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASS;
const fromDefault = process.env.EMAIL_FROM || (user ? `Help N Seek <${user}>` : "helpnseek@gmail.com");

// AWS SES API configuration (preferred for Railway)
const awsAccessKeyId = process.env.AWS_ACCESS_KEY_ID;
const awsSecretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
const awsRegion = process.env.AWS_REGION || process.env.SMTP_HOST?.match(/email-smtp\.([^.]+)\.amazonaws\.com/)?.[1] || "us-east-1";

// Determine if we should use AWS SES API (works on Railway) or SMTP
const useAwsSesApi = awsAccessKeyId && awsSecretAccessKey && (host?.includes("amazonaws.com") || host?.includes("email-smtp") || !host);
const isAwsSesHost = host?.includes("amazonaws.com") || host?.includes("email-smtp");

// Initialize AWS SES client if credentials are available
let sesClient = null;
if (useAwsSesApi) {
  try {
    sesClient = new SESClient({
      region: awsRegion,
      credentials: {
        accessKeyId: awsAccessKeyId,
        secretAccessKey: awsSecretAccessKey,
      },
    });
    console.log("[mail] AWS SES API client initialized (using HTTPS - works on Railway)", {
      region: awsRegion,
      from: fromDefault,
    });
  } catch (err) {
    console.error("[mail] Failed to initialize AWS SES API client:", err.message);
  }
}

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
    // Railway-specific warning for port 587
    if (port === 587) {
      console.warn("[mail] NOTE: Port 587 may be blocked by Railway. If connection fails, try port 465 (SSL)");
      console.warn("[mail] Set SMTP_PORT=465 in Railway environment variables if port 587 times out");
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
console.log("[mail] email configuration:", { 
  method: useAwsSesApi ? "AWS SES API (HTTPS)" : "SMTP",
  host: host || "NOT SET", 
  port: useAwsSesApi ? "N/A (using HTTPS)" : port, 
  user: user ? "****" : "NOT SET",
  configured: useAwsSesApi ? (sesClient !== null) : isSmtpConfigured,
  from: fromDefault,
  environment: process.env.NODE_ENV || "development",
  awsRegion: useAwsSesApi ? awsRegion : undefined,
  ...(useAwsSesApi ? {
    note: "Using AWS SES API - works on Railway (no SMTP port blocking)"
  } : isAwsSesHost ? {
    awsSesNote: "Using SMTP (may be blocked on Railway - consider switching to AWS SES API)",
    awsSesCredentialsNote: "To use AWS SES API instead, set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
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
    
    // Provide specific guidance for connection timeout errors
    if (err.code === "ETIMEDOUT" || err.code === "ECONNREFUSED" || err.code === "ECONNRESET") {
      if (host?.includes("amazonaws.com") || host?.includes("email-smtp")) {
        if (port === 587) {
          console.warn("[mail] ⚠️  CONNECTION TIMEOUT on port 587 - Railway often blocks this port!");
          console.warn("[mail] 🔧 SOLUTION: Switch to port 465 (SSL) in Railway:");
          console.warn("[mail]    1. Go to Railway dashboard > Variables");
          console.warn("[mail]    2. Set SMTP_PORT=465");
          console.warn("[mail]    3. Redeploy your service");
          console.warn("[mail]    4. Port 465 (SSL) is more reliable on Railway");
        }
      }
    }
    
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

// Send email using AWS SES API (preferred method for Railway)
async function sendEmailViaAwsSesApi({ to, subject, html, text, replyTo }) {
  if (!sesClient) {
    throw new Error("AWS SES API client is not initialized. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.");
  }

  // Extract email address from "Name <email>" format
  const extractEmail = (emailString) => {
    const match = emailString.match(/<(.+)>/);
    return match ? match[1] : emailString;
  };

  const fromEmail = extractEmail(fromDefault);
  const toEmail = extractEmail(to);

  const params = {
    Source: fromDefault,
    Destination: {
      ToAddresses: [toEmail],
    },
    Message: {
      Subject: {
        Data: subject,
        Charset: "UTF-8",
      },
      Body: {
        Html: {
          Data: html,
          Charset: "UTF-8",
        },
        ...(text ? {
          Text: {
            Data: text,
            Charset: "UTF-8",
          },
        } : {}),
      },
    },
    ...(replyTo ? { ReplyToAddresses: [extractEmail(replyTo)] } : {}),
  };

  try {
    const command = new SendEmailCommand(params);
    const response = await sesClient.send(command);
    
    console.log("[mail] email sent successfully via AWS SES API:", {
      to: toEmail,
      messageId: response.MessageId,
      requestId: response.$metadata.requestId,
    });

    // Return format compatible with nodemailer response
    return {
      messageId: response.MessageId,
      response: `250 Message accepted (MessageId: ${response.MessageId})`,
      accepted: [toEmail],
      rejected: [],
    };
  } catch (error) {
    // Enhanced error handling for AWS SES API
    if (error.name === "MessageRejected") {
      let errorMessage = "AWS SES rejected the email. ";
      if (error.message?.includes("Email address is not verified")) {
        errorMessage += "\n\n🔧 AWS SES is in sandbox mode. You can only send to verified email addresses.\n";
        errorMessage += "1. Wait for production access approval (check AWS SES Console > Account dashboard)\n";
        errorMessage += "2. Or verify the recipient email in AWS SES Console > Verified identities\n";
        errorMessage += "Current recipient: " + toEmail;
      } else {
        errorMessage += error.message || "Unknown rejection reason";
      }
      const rejectionError = new Error(errorMessage);
      rejectionError.code = "SES_MESSAGE_REJECTED";
      rejectionError.responseCode = 554;
      throw rejectionError;
    }
    throw error;
  }
}

// Send email
export async function sendEmail({ to, subject, html, text, replyTo }) {
  if (!to || !subject || !html) {
    throw new Error("sendEmail: 'to', 'subject', and 'html' are required");
  }

  // Use AWS SES API if available (works on Railway)
  if (useAwsSesApi && sesClient) {
    try {
      return await sendEmailViaAwsSesApi({ to, subject, html, text, replyTo });
    } catch (error) {
      // If AWS SES API fails, log and rethrow (don't fall back to SMTP)
      console.error("[mail] AWS SES API send failed:", {
        to,
        error: error.message,
        code: error.code,
        name: error.name,
      });
      throw error;
    }
  }

  // Fall back to SMTP for non-AWS providers
  if (!isSmtpConfigured || !transporter) {
    const error = new Error("Email is not configured. Please set either:\n" +
      "1. AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (for AWS SES API - recommended for Railway)\n" +
      "2. SMTP_HOST, SMTP_USER, and SMTP_PASS (for SMTP)");
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
    console.log("[mail] email sent successfully via SMTP:", {
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
        
        // Railway-specific guidance for connection timeouts
        if (error.code === "ETIMEDOUT" || error.code === "ECONNREFUSED") {
          errorMessage += "⚠️  CONNECTION TIMEOUT - Railway is blocking SMTP connections!\n";
          errorMessage += "\n🔧 BEST SOLUTION: Switch to AWS SES API (uses HTTPS - works on Railway):\n";
          errorMessage += "   1. In Railway, remove SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS\n";
          errorMessage += "   2. Add AWS credentials instead:\n";
          errorMessage += "      - AWS_ACCESS_KEY_ID (your AWS access key)\n";
          errorMessage += "      - AWS_SECRET_ACCESS_KEY (your AWS secret key)\n";
          errorMessage += "      - AWS_REGION (e.g., us-east-2)\n";
          errorMessage += "   3. Redeploy your service\n";
          errorMessage += "   4. AWS SES API uses HTTPS (port 443) which Railway allows\n\n";
          errorMessage += "   To get AWS credentials:\n";
          errorMessage += "   - Go to AWS Console > IAM > Users > Create user\n";
          errorMessage += "   - Attach policy: AmazonSESFullAccess\n";
          errorMessage += "   - Create access key and use those credentials\n\n";
        }
        
        errorMessage += "Alternative: Try port 465 (SSL) if you must use SMTP:\n";
        errorMessage += "   1. In Railway, set SMTP_PORT=465\n";
        errorMessage += "   2. Redeploy your service\n";
        errorMessage += "   3. Note: Port 465 may also be blocked on Railway\n\n";
        
        errorMessage += "Other SMTP troubleshooting:\n";
        errorMessage += "1. Verify SMTP_HOST is region-specific: email-smtp.{region}.amazonaws.com\n";
        errorMessage += "   ✓ Your current host looks correct: " + host + "\n";
        errorMessage += "2. Ensure you're using SMTP credentials (NOT AWS Access Keys)\n";
        errorMessage += "   - Create SMTP credentials in AWS SES Console > SMTP Settings\n";
        errorMessage += "   - Use the generated SMTP username and password\n";
        errorMessage += "3. Verify the sender email address in AWS SES (must be verified)\n";
        errorMessage += "   - Current sender: " + fromDefault + "\n";
        errorMessage += "   - This email must be verified in SES Console > Verified identities\n";
        errorMessage += "4. Check if SES is in sandbox mode (can only send to verified emails)\n";
        errorMessage += "5. Verify the AWS region matches your SES region\n";
        errorMessage += "6. Check AWS SES sending limits and quotas";
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
    
    // Check for AWS SES sandbox mode errors
    if (error.responseCode === 554 || 
        error.message?.includes("Email address is not verified") ||
        error.message?.includes("Account is in sandbox mode") ||
        error.response?.includes("Email address is not verified") ||
        error.response?.includes("Account is in sandbox mode")) {
      let sandboxErrorMessage = "AWS SES is in sandbox mode. You can only send emails to verified email addresses.\n\n";
      sandboxErrorMessage += "🔧 SOLUTIONS:\n";
      sandboxErrorMessage += "1. Wait for production access approval (you've already requested it)\n";
      sandboxErrorMessage += "   - Check AWS SES Console > Account dashboard for status\n";
      sandboxErrorMessage += "   - Usually approved within 24 hours\n";
      sandboxErrorMessage += "2. For testing: Verify the recipient email in AWS SES\n";
      sandboxErrorMessage += "   - Go to SES Console > Verified identities > Create identity\n";
      sandboxErrorMessage += "   - Add the email address you want to test with\n";
      sandboxErrorMessage += "   - Check inbox and click verification link\n";
      sandboxErrorMessage += "3. Once production access is approved, you can send to any email\n\n";
      sandboxErrorMessage += "Current recipient: " + to;
      
      const sandboxError = new Error(sandboxErrorMessage);
      sandboxError.code = "SES_SANDBOX_MODE";
      throw sandboxError;
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