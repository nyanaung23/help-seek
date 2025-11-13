import express from "express";
import { body, validationResult } from "express-validator";
import createError from "http-errors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "../models/User.js";
import { Otp } from "../models/Otp.js";
import { sendVerificationEmail } from "../utils/sendEmail.js";

const router = express.Router();

// Make sure email is UCSD email
function ucsdOnly(email) {
  return typeof email === "string" && email.toLowerCase().endsWith("@ucsd.edu");
}

// Genrate 5 digit OTP
function makeOtp() {
  return String(Math.floor(Math.random() * 100000)).padStart(5, "0");
}

// Temp signup token
function signSignupToken({ email, sub }) {
  const payload = { typ: "signup", email: String(email).toLowerCase() };
  if (sub) payload.sub = sub;
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: "30m" });
}

// Access token
function signAccessToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), email: user.email },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "1d" }
  );
}

// Temp reset token
function signResetToken(payload) {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: "10m" });
}

// Request code for signup
router.post(
  "/signup/request-code",
  body("email").isEmail(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) throw createError(400, { errors: errors.array() });
      const email = String(req.body.email).trim().toLowerCase();
      if (!ucsdOnly(email)) throw createError(400, "UCSD email required (@ucsd.edu)");

      const existing = await User.findOne({ email });
      if (existing && existing.verifiedAt) {
        return res
          .status(409)
          .json({ message: "Account already exists. Redirecting to log in." });
      }

      const code = makeOtp();
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

      await Otp.findOneAndUpdate(
        { email, type: "SIGNUP" },
        { email, type: "SIGNUP", code, expiresAt, attempts: 0 },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );

      // Send verification email (non-blocking but with error handling)
      // Return success immediately to avoid blocking the request
      sendVerificationEmail("signup", { to: email, name: "", code })
        .then((info) => {
          if (process.env.NODE_ENV !== "production") {
            console.log("[mail] signup code sent:", info.messageId);
          } else {
            console.log("[mail] signup code sent successfully to:", email);
          }
        })
        .catch((err) => {
          console.error("[mail] signup code failed:", err.message);
          // Delete the OTP since email failed
          Otp.deleteOne({ email, type: "SIGNUP" }).catch((deleteErr) => {
            console.error("[mail] Failed to delete OTP after email error:", deleteErr.message);
          });
        });

      // Return immediately - email is sent asynchronously
      return res.json({ message: "Code sent", next: "verify-code" });
    } catch (err) {
      next(err);
    }
  }
);

// Email verification code for signup
router.post(
  "/signup/verify-code",
  body("email").isEmail(),
  body("code").isLength({ min: 5, max: 5 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) throw createError(400, { errors: errors.array() });

      const email = String(req.body.email).trim().toLowerCase();
      const code = String(req.body.code).trim();

      const otp = await Otp.findOne({ email, type: "SIGNUP" });
      if (!otp) throw createError(400, "Code expired or not found. Request a new one.");

      if (otp.expiresAt.getTime() < Date.now()) {
        await Otp.deleteOne({ _id: otp._id });
        throw createError(400, "Code expired. Request a new one.");
      }

      if (otp.code !== code) {
        otp.attempts = (otp.attempts || 0) + 1;
        await otp.save();
        if (otp.attempts >= 5) {
          await Otp.deleteOne({ _id: otp._id });
          throw createError(429, "Too many attempts. Request a new code.");
        }
        throw createError(401, "Invalid code.");
      }

      const existing = await User.findOne({ email });
      const signupToken = signSignupToken({
        email,
        sub: existing ? existing._id.toString() : undefined,
      });

      await Otp.deleteMany({ email, type: "SIGNUP" });

      res.json({ message: "Email verified", next: "complete", signupToken, email });
    } catch (err) {
      next(err);
    }
  }
);

// Complete signup
router.post(
  "/signup/complete",
  body("firstName").isString().isLength({ min: 1 }),
  body("lastName").isString().isLength({ min: 1 }),
  body("password").isLength({ min: 8 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) throw createError(400, { errors: errors.array() });

      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (!token) throw createError(401, "Missing signup token");

      let payload;
      try {
        payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      } catch {
        throw createError(401, "Invalid or expired signup token");
      }
      if (payload.typ !== "signup") throw createError(401, "Wrong token type");

      const email = String(payload.email).toLowerCase();
      const { firstName, lastName, password } = req.body;

      let user = null;
      if (payload.sub) user = await User.findById(payload.sub);
      if (!user) user = await User.findOne({ email });
      if (!user) {
        user = new User({ email, emailDomain: "ucsd.edu" });
      }

      user.name = `${String(firstName).trim()} ${String(lastName).trim()}`;
      user.passwordHash = await bcrypt.hash(password, 12);
      user.verifiedAt = user.verifiedAt || new Date();
      await user.save();

      const accessToken = signAccessToken(user);
      return res.status(201).json({
        message: "Signup complete",
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          college: user.college,
          year: user.year,
        },
        accessToken,
        expiresIn: 24 * 60 * 60,
      });
    } catch (err) {
      next(err);
    }
  }
);

// Login
router.post(
  "/login",
  body("email").isEmail(),
  body("password").isString(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) throw createError(400, { errors: errors.array() });

      const email = String(req.body.email).trim().toLowerCase();
      const { password } = req.body;

      const user = await User.findOne({ email });
      if (!user) throw createError(401, "Your password is incorrect or this account does not exist.");
      if (!user.verifiedAt) throw createError(403, "Please verify your email to continue.");

      const ok = await bcrypt.compare(password, user.passwordHash || "");
      if (!ok) throw createError(401, "Your password is incorrect or this account does not exist.");

      const accessToken = signAccessToken(user);
      res.status(201).json({
        message: "Login successful",
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          college: user.college,
          year: user.year,
        },
        accessToken,
        expiresIn: 24 * 60 * 60,
      });
    } catch (err) {
      next(err);
    }
  }
);

// Logout
router.post("/logout", async (_req, res) => {
  res.clearCookie("access_token");
  res.json({ message: "Logged out" });
});

// Email varification code for forgot password
router.post(
  "/forgot-password/request-code",
  body("email").isEmail(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ message: "Invalid email" });
      const email = String(req.body.email).trim().toLowerCase();
      if (!ucsdOnly(email)) return res.status(400).json({ message: "UCSD email required (@ucsd.edu)" });

      const user = await User.findOne({ email });
      if (!user) return res.status(404).json({ message: "Account not found" });

      const code = makeOtp();
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

      await Otp.findOneAndUpdate(
        { email, type: "FORGOT" },
        { email, type: "FORGOT", code, expiresAt, attempts: 0 },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );

      // Send verification email (non-blocking but with error handling)
      // Return success immediately to avoid blocking the request
      sendVerificationEmail("forgot", { to: email, name: user?.name || "", code })
        .then((info) => {
          if (process.env.NODE_ENV !== "production") {
            console.log("[mail] forgot code sent:", info.messageId);
          } else {
            console.log("[mail] forgot code sent successfully to:", email);
          }
        })
        .catch((err) => {
          console.error("[mail] forgot code failed:", err.message);
          // Delete the OTP since email failed
          Otp.deleteOne({ email, type: "FORGOT" }).catch((deleteErr) => {
            console.error("[mail] Failed to delete OTP after email error:", deleteErr.message);
          });
        });

      // Return immediately - email is sent asynchronously
      return res.json({ message: "sent" });
    } catch (err) {
      next(err);
    }
  }
);

// Verify code for forgot password
router.post(
  "/forgot-password/verify-code",
  body("email").isEmail(),
  body("code").isLength({ min: 5, max: 5 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ message: "Invalid request" });

      const email = String(req.body.email).trim().toLowerCase();
      const code = String(req.body.code).trim();

      const otp = await Otp.findOne({ email, type: "FORGOT" });
      if (!otp) return res.status(400).json({ message: "Invalid or expired code" });

      if (otp.expiresAt.getTime() < Date.now()) {
        await Otp.deleteOne({ _id: otp._id });
        return res.status(400).json({ message: "Invalid or expired code" });
      }

      if (otp.code !== code) {
        otp.attempts = (otp.attempts || 0) + 1;
        await otp.save();
        if (otp.attempts >= 5) {
          await Otp.deleteOne({ _id: otp._id });
          return res.status(429).json({ message: "Too many attempts. Request a new code." });
        }
        return res.status(401).json({ message: "Invalid code" });
      }

      const resetToken = signResetToken({ typ: "pwreset", email });
      await Otp.deleteOne({ _id: otp._id });

      return res.json({ resetToken });
    } catch (err) {
      next(err);
    }
  }
);

// Reset password
router.post(
  "/forgot-password/reset",
  body("password").optional().isLength({ min: 8 }),
  body("newPassword").optional().isLength({ min: 8 }),
  body("email").optional({ nullable: true, checkFalsy: true }).isEmail(), // FIX: relaxed optional
  body("resetToken").optional().isString(),
  async (req, res, next) => {
    try {
      console.log("HIT unified /forgot-password/reset", {
        hasAuth: Boolean((req.headers.authorization || "").startsWith("Bearer ")),
        body: req.body,
      });

      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ message: "Invalid request" });

      let token = null;
      const auth = req.headers.authorization || "";
      if (auth.startsWith("Bearer ")) token = auth.slice(7);
      if (!token && req.body.resetToken) token = String(req.body.resetToken);
      if (!token) return res.status(401).json({ message: "Missing reset token" });

      const newPassword = req.body.password ?? req.body.newPassword;
      if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({ message: "Invalid request" });
      }

      let payload;
      try {
        payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      } catch {
        return res.status(400).json({ message: "Invalid or expired reset token" });
      }

      if (payload.typ !== "pwreset") {
        return res.status(400).json({ message: "Invalid reset token type" });
      }

      const emailFromToken = String(payload.email).toLowerCase();

      // normalize optional email from body
      const emailFromBodyRaw = req.body.email;
      const emailFromBody =
        typeof emailFromBodyRaw === "string" && emailFromBodyRaw.trim()
          ? emailFromBodyRaw.trim().toLowerCase()
          : null;

      if (emailFromBody && emailFromBody !== emailFromToken) {
        return res.status(400).json({ message: "Reset token does not match email" });
      }

      const user = await User.findOne({ email: emailFromToken });
      if (!user) return res.status(404).json({ message: "Account not found" });

      const samePassword = await bcrypt.compare(newPassword, user.passwordHash || "");
      if (samePassword) {
        return res
          .status(409)
          .json({ message: "Please choose a new password that you have never used before." });
      }

      user.passwordHash = await bcrypt.hash(newPassword, 12);
      await user.save();

      return res.json({ message: "ok" });
    } catch (err) {
      next(err);
    }
  }
);

export default router;