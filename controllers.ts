/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import { GoogleGenAI } from "@google/genai";
import { dbInstance, User, UserProgress, Course } from "./db";

// Load Environment Keys
const JWT_SECRET = process.env.JWT_SECRET || "sixsigma-super-secure-token-secret-98431";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";

// Stripe Initialization with Guard
let stripeClient: Stripe | null = null;
if (STRIPE_SECRET_KEY) {
  try {
    stripeClient = new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: "2025-02-24T00:00:00" as any, // Standard sandbox api-version
    });
  } catch (err) {
    console.error("Stripe initialization failed:", err);
  }
}

// Gemini Initialization with Guard and telemetry User-Agent
let aiClient: GoogleGenAI | null = null;
if (GEMINI_API_KEY) {
  try {
    aiClient = new GoogleGenAI({
      apiKey: GEMINI_API_KEY,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  } catch (err) {
    console.error("Gemini AI client initialization failed:", err);
  }
}

// ---------------------------------------------------------
// 1. JWT Authentication Controller Class
// ---------------------------------------------------------
export class AuthController {
  static async signup(req: Request, res: Response): Promise<void> {
    try {
      const { name, email, password, branch, track } = req.body;

      if (!name || !email || !password || !branch || !track) {
        res.status(400).json({ error: "Missing required profile fields for registration." });
        return;
      }

      const users = dbInstance.getUsers();
      const existingUser = users.find((u) => u.email.toLowerCase() === email.toLowerCase());
      if (existingUser) {
        res.status(409).json({ error: "An account with this email already exists." });
        return;
      }

      // Hash password securely with bcryptjs
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);

      const newUser: User = {
        id: "usr_" + Math.random().toString(36).substr(2, 9),
        name,
        email: email.toLowerCase(),
        passwordHash,
        branch,
        track,
        isPremiumUnlocked: false, // Default: unlock premium via mock checkout or stripe webhook
        createdAt: new Date().toISOString(),
      };

      dbInstance.saveUsers([...users, newUser]);

      // Generate secure session tracking token
      const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: "7d" });

      // Omit password hash in client response
      const { passwordHash: _, ...userSafe } = newUser;
      res.status(201).json({
        message: "Engineering student registration successful.",
        user: userSafe,
        token,
      });
    } catch (err: any) {
      res.status(500).json({ error: "Internal server registration failure: " + err.message });
    }
  }

  static async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        res.status(400).json({ error: "Please log in with both email and password." });
        return;
      }

      const users = dbInstance.getUsers();
      const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase());
      if (!user) {
        res.status(401).json({ error: "Invalid email or login credentials." });
        return;
      }

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) {
        res.status(401).json({ error: "Invalid password credentials." });
        return;
      }

      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });

      const { passwordHash: _, ...userSafe } = user;
      res.json({
        message: "Successfully logged in to Sixsigma AI platform.",
        user: userSafe,
        token,
      });
    } catch (err: any) {
      res.status(500).json({ error: "Internal login router execution error: " + err.message });
    }
  }

  static getProfile(req: Request, res: Response): void {
    // Retrives current user context loaded by the Authorization middleware
    const user = (req as any).user;
    if (!user) {
      res.status(404).json({ error: "Profile session was not found." });
      return;
    }
    const { passwordHash: _, ...userSafe } = user;
    res.json(userSafe);
  }
}

// ---------------------------------------------------------
// 2. User Data & Progress Tracking Controller Class
// ---------------------------------------------------------
export class ProgressController {
  static getProgress(req: Request, res: Response): void {
    try {
      const user = (req as any).user;
      const progressList = dbInstance.getProgress().filter((p) => p.userId === user.id);
      res.json(progressList);
    } catch (err: any) {
      res.status(500).json({ error: "Failed to retrieve module progress metadata: " + err.message });
    }
  }

  static updateProgress(req: Request, res: Response): void {
    try {
      const user = (req as any).user;
      const { courseId, lessonId, completed, watchPercent, score } = req.body;

      if (!courseId || !lessonId) {
        res.status(400).json({ error: "Missing required course or module targets." });
        return;
      }

      const progressRecords = dbInstance.getProgress();
      const existingRecordIndex = progressRecords.findIndex(
        (p) => p.userId === user.id && p.courseId === courseId && p.lessonId === lessonId
      );

      const now = new Date().toISOString();

      if (existingRecordIndex > -1) {
        // Update existing record
        progressRecords[existingRecordIndex] = {
          ...progressRecords[existingRecordIndex],
          completed: completed !== undefined ? completed : progressRecords[existingRecordIndex].completed,
          watchPercent: watchPercent !== undefined ? watchPercent : progressRecords[existingRecordIndex].watchPercent,
          score: score !== undefined ? score : progressRecords[existingRecordIndex].score,
          updatedAt: now,
        };
      } else {
        // Create new progress entry
        const newProgress: UserProgress = {
          id: "prg_" + Math.random().toString(36).substr(2, 9),
          userId: user.id,
          courseId,
          lessonId,
          completed: !!completed,
          watchPercent: watchPercent || 0,
          score: score !== undefined ? score : undefined,
          updatedAt: now,
        };
        progressRecords.push(newProgress);
      }

      dbInstance.saveProgress(progressRecords);
      res.json({ message: "Lesson progress sync success.", progress: progressRecords.filter((p) => p.userId === user.id) });
    } catch (err: any) {
      res.status(500).json({ error: "Error committing student tracking metrics: " + err.message });
    }
  }
}

// ---------------------------------------------------------
// 3. Payment Gateway Integration Controller Class (Stripe + Sandbox Simulation Webhook)
// ---------------------------------------------------------
export class PaymentController {
  static async createCheckoutSession(req: Request, res: Response): Promise<void> {
    try {
      const user = (req as any).user;
      const { courseId } = req.body;

      if (!courseId) {
        res.status(400).json({ error: "Please specify target program for Stripe check-out." });
        return;
      }

      const courses = dbInstance.getCourses();
      const course = courses.find((c) => c.id === courseId);
      if (!course) {
        res.status(404).json({ error: "Identified engineering syllabus course was not found." });
        return;
      }

      // If Stripe client is set up, create actual secure checkout session
      if (stripeClient) {
        const appUrl = process.env.APP_URL || `http://localhost:3000`;
        const session = await stripeClient.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: `Sixsigma AI PG: ${course.title}`,
                  description: `${course.duration} comprehensive course in ${course.branch}`,
                },
                unit_amount: 4900, // $49.00 USD flat premium upgrade
              },
              quantity: 1,
            },
          ],
          mode: "payment",
          success_url: `${appUrl}/dashboard?payment=success&courseId=${courseId}`,
          cancel_url: `${appUrl}/pricing?payment=cancelled`,
          metadata: {
            userId: user.id,
            courseId: courseId,
          },
        });

        res.json({ url: session.url, isSimulation: false });
        return;
      }

      // Seamless sandbox preview simulator setup: We pass a gorgeous, interactive mockup link
      // that permits webhook debugging directly within the browser view.
      res.json({
        url: `/payment-simulation?courseId=${courseId}&userId=${user.id}`,
        isSimulation: true,
        message: "Stripe sandbox checkout generated. Connecting client to interactive Stripe card debugger.",
      });
    } catch (err: any) {
      res.status(500).json({ error: "Stripe process integration error: " + err.message });
    }
  }

  /**
   * Stripe Live Webhook Handler securely verifying signatures.
   * If local test simulation handles it, we also expose a simulator route below.
   */
  static async handleWebhook(req: Request, res: Response): Promise<void> {
    const sig = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || "";

    if (!stripeClient) {
      res.status(400).json({ error: "Stripe API Key is unconfigured. Webhook cannot verify signatures." });
      return;
    }

    let event: Stripe.Event;

    try {
      event = stripeClient.webhooks.constructEvent(
        (req as any).rawBody || req.body,
        sig as string,
        webhookSecret
      );
    } catch (err: any) {
      console.warn("Webhook signature checking failed. Trace:", err.message);
      res.status(400).send(`Stripe verification failure: ${err.message}`);
      return;
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object as Stripe.Checkout.Session;
      const userId = session.metadata?.userId;
      const courseId = session.metadata?.courseId;

      if (userId) {
        const users = dbInstance.getUsers();
        const userIndex = users.findIndex((u) => u.id === userId);
        if (userIndex > -1) {
          users[userIndex].isPremiumUnlocked = true;
          dbInstance.saveUsers(users);
          console.log(`Unlocked premium courses for user ${userId} via secure Stripe webhook.`);
        }
      }
    }

    res.json({ received: true });
  }

  /**
   * Safe payment simulator API to let students unlock courses directly
   * if they test our Stripe session model in standard workspace mode.
   */
  static triggerSimulatedSuccess(req: Request, res: Response): void {
    try {
      const { userId, courseId } = req.body;

      if (!userId || !courseId) {
        res.status(400).json({ error: "Invalid mock checkout metadata" });
        return;
      }

      const users = dbInstance.getUsers();
      const userIndex = users.findIndex((u) => u.id === userId);

      if (userIndex > -1) {
        users[userIndex].isPremiumUnlocked = true;
        dbInstance.saveUsers(users);
        res.json({
          status: "success",
          message: "Simulator Webhook successfully received a simulated checkout.session.completed event. Your Sixsigma AI premium engineering courses have been permanently unlocked!",
        });
      } else {
        res.status(404).json({ error: "Identified student record was not found." });
      }
    } catch (err: any) {
      res.status(500).json({ error: "Mocking trigger failure: " + err.message });
    }
  }
}

// ---------------------------------------------------------
// 4. Gemini AI Tutor Chatbot Controller Class
// ---------------------------------------------------------
export const AiController = {
  async chatMessage(req: Request, res: Response): Promise<void> {
    try {
      const user = (req as any).user;
      const { message, chatHistory } = req.body;

      if (!message) {
        res.status(400).json({ error: "Chat message must not be empty." });
        return;
      }

      // Check if user has uploaded a real Gemini Key. If not, generate high-fidelity simulated response
      // explaining how they can easily connect theirs with zero crashing!
      if (!aiClient) {
        // High fidelity simulated answer with real tutoring logic based on track + branch!
        const simulationReply = await simulateAiTutor(user, message);
        res.json({
          message: simulationReply,
          isMocked: true,
          notice: "Tutoring generated via local expert system. Connect GEMINI_API_KEY in Settings Secrets to activate interactive AI.",
        });
        return;
      }

      const systemInstruction = `You are "Sixsigma AI Tutor", an elite engineering mentor and placement coach at the Sixsigma AI Institute.
The current student is ${user.name}, who is categorized in the ${user.track} Track of the ${user.branch} Engineering department.
Guidelines:
1. Provide extremely detailed, industry-aligned answers with actual steps, equations, or code snippets.
2. Tailor tone to history track:
   - For Freshers: Focus on landing jobs, foundational engineering concepts, clearing technical panels, and resume keywords.
   - For Experienced: Focus on career promotions, systems integration, advanced metrics, and Industry 4.0 upskilling.
   - For Managers: Focus on corporate strategy, team operations, Return on Investment (ROI), risk matrices, and Six Sigma program deployments.
3. Incorporate relevant Process Excellence frameworks (Lean, Kaizen, 5S, Six Sigma DMAIC) where possible.
Always structure recommendations with clean markdown format. Maintain high instructional authority.`;

      const response = await aiClient.models.generateContent({
        model: "gemini-3.5-flash",
        contents: [
          ...(chatHistory || []).map((h: any) => ({
            role: h.role === "assistant" ? "model" : "user",
            parts: [{ text: h.text }],
          })),
          { role: "user", parts: [{ text: message }] }
        ],
        config: {
          systemInstruction,
          temperature: 0.7,
        },
      });

      res.json({
        message: response.text || "I was unable to formulate a response at this time.",
        isMocked: false,
      });
    } catch (err: any) {
      res.status(500).json({ error: "Gemini server coordinator error: " + err.message });
    }
  },
};

/**
 * High-fidelity fallback simulated AI response when GEMINI_API_KEY is not configured,
 * ensuring students have a lovely interactive prompt immediately.
 */
function simulateAiTutor(user: any, userMsg: string): Promise<string> {
  return new Promise((resolve) => {
    setTimeout(() => {
      const promptLower = userMsg.toLowerCase();
      let response = `### Sixsigma AI Fallback Mentor Session (${user.branch} Department)\n\n`;

      if (promptLower.includes("hello") || promptLower.includes("hi") || promptLower.includes("help")) {
        response += `Welcome back, **${user.name}**! As an engineering student on the **${user.track} Track** in **${user.branch} Engineering**, I am here 24/7 to help resolve your doubts, conduct mock assessments, or review your placement preparation.\n\n`;
        response += `We are currently focusing on specialized modules and **Six Sigma continuous improvement** methodologies. What topic can I help you master today?\n\n`;
        response += `*Try asking: "How do I optimize smart grid loads?", "Tell me about cell balancing", or "How can I integrate Kaizen on my shop floor?"*`;
      } else if (promptLower.includes("grid") || promptLower.includes("electrical")) {
        response += `#### Technical Optimization: Smart Grid Efficiency\n\n`;
        response += `Smart Grid control relies heavily on real-time feedback loops. To achieve optimum alignment:\n\n`;
        response += `1. **Phasor Measurement Units (PMUs):** Capture grid voltage and current waves at up to 50 samples/second.\n`;
        response += `2. **DMAIC Application:** Under standard Yellow Belt parameters, apply SPC control limits to frequency jitter to trigger load shedding dynamically.\n\n`;
        response += `What specific circuit configuration or automated scada control parameter would you like to review?`;
      } else if (promptLower.includes("balancing") || promptLower.includes("bms") || promptLower.includes("ev")) {
        response += `#### EV Battery Balancing Deep-Dive\n\n`;
        response += `Active vs Passive Battery Management Systems (BMS):\n\n`;
        response += `- **Passive Balancing:** Dissipates energy from highest-voltage cells through bypass power resistors as heat. It is low cost but thermally inefficient.\n`;
        response += `- **Active Balancing:** Uses capacitive or inductive shuttles to transfer energy from stronger cells to weaker cells. Highly efficient, reducing grid charger wear.\n\n`;
        response += `Would you like me to draw up a Matlab/Simulink calibration script comparison?`;
      } else if (promptLower.includes("kaizen") || promptLower.includes("sigma") || promptLower.includes("lean")) {
        response += `#### Industrial Process Excellence\n\n`;
        response += `Integrating Six Sigma DMAIC into **${user.branch} Engineering** operations yields immense ROI:\n\n`;
        response += `1. **Define:** Outline the scrap rate or downtime baseline.\n`;
        response += `2. **Measure:** Track OEE (Overall Equipment Effectiveness) systematically.\n`;
        response += `3. **Analyze:** Run fishbone/Ishikawa diagnostics, listing potential root causes for cycle delays.\n\n`;
        response += `As a **${user.track}**, apply this standard template in your upcoming Capstone assignment.`;
      } else {
        response += `#### Academic Mentor Response\n\n`;
        response += `You asked: *"${userMsg}"*\n\n`;
        response += `Excellent engineering question. To master this component on your **${user.track}** progression, keep these three elements in mind:\n\n`;
        response += `1. **Define Constraints:** Always translate CAD, electrical circuitry, or structural stress margins into clean quantitative limitations before programming.\n`;
        response += `2. **Simulate Early:** Leverage MATLAB / Simulink, SolidWorks, or STAAD.Pro to evaluate behavior prior to physically tooling.\n`;
        response += `3. **Quality Alignment:** Standardize measurements under the **5S parameters** to assure a secure, reliable workspace.\n\n`;
        response += `Let me know if you would like me to deep-dive into any specialized branch calculations!`;
      }

      resolve(response);
    }, 400);
  });
}
