/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import dotenv from "dotenv";
import apiRouter from "./backend/routes";

// Load Environment Configuration
dotenv.config();

const app = express();
const PORT = 3000;

// =========================================================
// 1. Stripe Raw Body Parser Middleware
// =========================================================
// Stripe signature validation demands the exact unparsed raw buffer of the request body.
// We intercept /api/payments/webhook before standard body parsers read it.
app.use(
  "/api/payments/webhook",
  express.raw({ type: "application/json" }),
  (req: any, _res: Response, next: NextFunction) => {
    req.rawBody = req.body;
    next();
  }
);

// Standard JSON and URL-encoded parsers for other routes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =========================================================
// 2. CORS Configuration
// =========================================================
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization", "stripe-signature"],
  credentials: true
}));

// =========================================================
// 3. Register Modular Backend REST API Router
// =========================================================
app.use("/api", apiRouter);

// Database Health Status & Standard Landing Route
app.get("/api/health", (_req: Request, res: Response) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

app.get("/", (_req: Request, res: Response) => {
  res.json({
    message: "SixSigma AI Backend API is online.",
    apiRoot: "/api",
    endpoints: [
      "/api/courses",
      "/api/auth/signup",
      "/api/auth/login",
      "/api/auth/me",
      "/api/user/progress",
      "/api/payments/checkout",
      "/api/payments/webhook",
      "/api/ai/chat"
    ]
  });
});

// App listener
app.listen(PORT, "0.0.0.0", () => {
  console.log(`===================================================`);
  console.log(` SixSigma AI Platform Backend online at http://0.0.0.0:${PORT}`);
  console.log(` API Root: http://0.0.0.0:${PORT}/api`);
  console.log(`===================================================`);
});
