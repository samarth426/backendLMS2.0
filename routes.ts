/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Router, Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { rateLimit } from "express-rate-limit";
import { dbInstance } from "./db";
import {
  AuthController,
  ProgressController,
  PaymentController,
  AiController,
} from "./controllers";

const JWT_SECRET = process.env.JWT_SECRET || "sixsigma-super-secure-token-secret-98431";
const router = Router();

// =========================================================
// 1. JWT Authentication Middleware
// =========================================================
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Format: Bearer <JWT_TOKEN>

  if (!token) {
    res.status(401).json({ error: "Access denied. Authentication token not provided." });
    return;
  }

  jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
    if (err) {
      res.status(403).json({ error: "Invalid, expired, or compromised session token." });
      return;
    }

    const users = dbInstance.getUsers();
    const user = users.find((u) => u.id === decoded.userId);
    if (!user) {
      res.status(404).json({ error: "The student account associated with this token was not found." });
      return;
    }

    // Attach authenticated user to the request context
    (req as any).user = user;
    next();
  });
}

// =========================================================
// 2. Security Rate Limiters for Sensitive Endpoints
// =========================================================
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minutes
  max: 200, // Permit max 200 requests per 15 min for testing within client scope
  message: { error: "Too many login attempts. Please wait 15 minutes before retrying." },
  standardHeaders: true,
  legacyHeaders: false,
});

const checkoutRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 50,
  message: { error: "Simulated payment throttling activated. Try again shortly." },
});

// =========================================================
// 3. Mount Routes
// =========================================================

// Public Curriculum Route
router.get("/courses", (req: Request, res: Response) => {
  try {
    const courses = dbInstance.getCourses();
    res.json(courses);
  } catch (err: any) {
    res.status(500).json({ error: "Failed to load public courses schema: " + err.message });
  }
});

// Authentication Endpoints
router.post("/auth/signup", AuthController.signup);
router.post("/auth/login", authRateLimiter, AuthController.login);
router.get("/auth/me", authenticateToken, AuthController.getProfile);

// Progress Tracking Endpoints
router.get("/user/progress", authenticateToken, ProgressController.getProgress);
router.post("/user/progress", authenticateToken, ProgressController.updateProgress);

// Payment Checkout & Webhook Integration Endpoints
router.post("/payments/checkout", authenticateToken, checkoutRateLimiter, PaymentController.createCheckoutSession);
router.post("/payments/webhook", PaymentController.handleWebhook);
router.post("/payments/simulate-success", authenticateToken, PaymentController.triggerSimulatedSuccess);

// AI Tutor Chatbot Integration Endpoints
router.post("/ai/chat", authenticateToken, AiController.chatMessage);

export default router;
