import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";
import cors from "cors";
import pg from "pg";

import { ipqsUrlCheck, ipqsEmailCheck } from "./ipqs.js";
import {
  detectMime,
  extractTextFromBuffer,
  extractUrlsFromText
} from "./ocr.js";

import authRoutes from "./routes/auth.js";

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

const PORT = process.env.PORT || 8080;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "https://scamdefender.ai";

const API_KEYS = (process.env.API_KEYS || "")
  .split(",")
  .map(k => k.trim())
  .filter(Boolean);

const FREE_DAILY_LIMIT = Number(process.env.FREE_DAILY_LIMIT || "500");

// Postgres pool
const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL
});

const keyUsage = new Map();

function todayString() {
  return new Date().toISOString().slice(0, 10);
}

// -----------------------------------------------------------------------------
// Express App Setup
// -----------------------------------------------------------------------------

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120
  })
);

// CORS — must come BEFORE your routes
app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? "*" : [CORS_ORIGIN],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-scamdefender-key"],
    credentials: false
  })
);

app.options("*", cors());

app.use(bodyParser.json({ limit: "5mb" }));

// Mount authentication routes BEFORE protection middleware
app.use("/auth", authRoutes);

// -----------------------------------------------------------------------------
// Auth and Metering Middleware
// -----------------------------------------------------------------------------

function authAndMeter(req, res, next) {
  if (!API_KEYS.length) return next();

  const headerKey =
    req.header("x-scamdefender-key") || req.header("X-ScamDefender-Key");

  if (!headerKey || !API_KEYS.includes(headerKey)) {
    return res.status(401).json({
      error: "missing or invalid API key",
      code: "unauthorized"
    });
  }

  const today = todayString();
  let usage = keyUsage.get(headerKey);

  if (!usage || usage.day !== today) {
    usage = {
      day: today,
      dayCount: 0,
      total: usage?.total ?? 0
    };
  }

  usage.dayCount += 1;
  usage.total += 1;

  keyUsage.set(headerKey, usage);

  if (usage.dayCount > FREE_DAILY_LIMIT) {
    return res.status(429).json({
      error: "daily limit exceeded",
      code: "rate_limited",
      limit: FREE_DAILY_LIMIT,
      dayCount: usage.dayCount
    });
  }

  req.apiKey = headerKey;
  req.apiUsage = usage;

  next();
}

// -----------------------------------------------------------------------------
// Status
// -----------------------------------------------------------------------------

app.get("/healthz", (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// -----------------------------------------------------------------------------
// /v1/check URL + text
// -----------------------------------------------------------------------------

app.post("/v1/check", authAndMeter, async (req, res) => {
  try {
    const { input_type = "url", content, source, client_id } = req.body;
    if (!content) return res.status(400).json({ error: "missing content" });

    const result = await ipqsUrlCheck(content, { strictness: 1 });

    await db.query(
      `INSERT INTO scans (input_type, content_excerpt, file_name, mime_type,
        api_key, day_count, total_count, verdict, confidence, evidence, next_steps, meta)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        input_type,
        String(content).slice(0, 200),
        null,
        null,
        req.apiKey,
        req.apiUsage?.dayCount ?? null,
        req.apiUsage?.total ?? null,
        result.verdict,
        result.confidence,
        JSON.stringify(result.evidence),
        JSON.stringify(result.next_steps),
        JSON.stringify({ ...result.meta, source, client_id })
      ]
    );

    res.json(result);
  } catch (err) {
    console.error("Error /v1/check:", err);
    res.status(500).json({ error: "internal error" });
  }
});

// -----------------------------------------------------------------------------
// /v1/check_email
// -----------------------------------------------------------------------------

app.post("/v1/check_email", authAndMeter, async (req, res) => {
  try {
    const { input_type = "email", content, source, client_id } = req.body;
    if (!content) return res.status(400).json({ error: "missing content" });

    const result = await ipqsEmailCheck(content, { strictness: 1 });

    await db.query(
      `INSERT INTO scans (input_type, content_excerpt, file_name, mime_type,
        api_key, day_count, total_count, verdict, confidence, evidence, next_steps, meta)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        input_type,
        String(content).slice(0, 200),
        null,
        null,
        req.apiKey,
        req.apiUsage?.dayCount ?? null,
        req.apiUsage?.total ?? null,
        result.verdict,
        result.confidence,
        JSON.stringify(result.evidence),
        JSON.stringify(result.next_steps),
        JSON.stringify({ ...result.meta, source, client_id })
      ]
    );

    res.json(result);
  } catch (err) {
    console.error("Error /v1/check_email:", err);
    res.status(500).json({ error: "internal error" });
  }
});

// -----------------------------------------------------------------------------
// /v1/check_file — unchanged from your original
// -----------------------------------------------------------------------------
app.post("/v1/check_file", authAndMeter, async (req, res) => {
  // your entire existing file scanner code here, unchanged
  // I am not altering this because it already works
  // copy and paste your original block exactly
});

// -----------------------------------------------------------------------------
// Admin dashboard — keep exactly as it is
// -----------------------------------------------------------------------------

app.get("/admin", async (req, res) => {
  // leave unchanged
});

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`ScamDefender API listening on ${PORT}`);
});