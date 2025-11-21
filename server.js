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

// ============================================================================
// CONFIG
// ============================================================================

const PORT = process.env.PORT || 8080;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "https://scamdefender.ai";

const API_KEYS = (process.env.API_KEYS || "")
  .split(",")
  .map(k => k.trim())
  .filter(Boolean);

const FREE_DAILY_LIMIT = Number(process.env.FREE_DAILY_LIMIT || "500");

const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL
});

const keyUsage = new Map();

function todayString() {
  return new Date().toISOString().slice(0, 10);
}

// ============================================================================
// EXPRESS APP SETUP
// ============================================================================

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

// IMPORTANT: CORS MUST COME BEFORE ALL ROUTES INCLUDING /auth
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

// Mount authentication routes
// These become:
//   POST /auth/signup
//   POST /auth/login
app.use("/auth", authRoutes);

// ============================================================================
// AUTH AND METERING FOR SCANNER ENDPOINTS
// ============================================================================

function authAndMeter(req, res, next) {
  if (!API_KEYS.length) return next(); // open mode

  const key =
    req.header("x-scamdefender-key") || req.header("X-ScamDefender-Key");

  if (!key || !API_KEYS.includes(key)) {
    return res.status(401).json({ error: "missing or invalid API key" });
  }

  const today = todayString();
  let usage = keyUsage.get(key);

  if (!usage || usage.day !== today) {
    usage = {
      day: today,
      dayCount: 0,
      total: usage?.total ?? 0
    };
  }

  usage.dayCount += 1;
  usage.total += 1;

  keyUsage.set(key, usage);

  if (usage.dayCount > FREE_DAILY_LIMIT) {
    return res.status(429).json({
      error: "daily limit exceeded",
      dayCount: usage.dayCount,
      limit: FREE_DAILY_LIMIT
    });
  }

  req.apiKey = key;
  req.apiUsage = usage;

  next();
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get("/healthz", (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// ============================================================================
// URL + TEXT SCAN
// ============================================================================

app.post("/v1/check", authAndMeter, async (req, res) => {
  try {
    const { input_type = "url", content, source, client_id } = req.body || {};
    if (!content) return res.status(400).json({ error: "missing content" });

    const result = await ipqsUrlCheck(content, { strictness: 1 });

    await db.query(
      `INSERT INTO scans
       (input_type, content_excerpt, file_name, mime_type,
        api_key, day_count, total_count,
        verdict, confidence, evidence, next_steps, meta)
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
        JSON.stringify({ ...(result.meta || {}), source, client_id })
      ]
    );

    res.json(result);
  } catch (err) {
    console.error("Error in /v1/check:", err);
    res.status(500).json({ error: "internal error" });
  }
});

// ============================================================================
// EMAIL CHECK
// ============================================================================

app.post("/v1/check_email", authAndMeter, async (req, res) => {
  try {
    const { input_type = "email", content, source, client_id } = req.body || {};
    if (!content) return res.status(400).json({ error: "missing content" });

    const result = await ipqsEmailCheck(content, { strictness: 1 });

    await db.query(
      `INSERT INTO scans
       (input_type, content_excerpt, file_name, mime_type,
        api_key, day_count, total_count,
        verdict, confidence, evidence, next_steps, meta)
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
        JSON.stringify({ ...(result.meta || {}), source, client_id })
      ]
    );

    res.json(result);
  } catch (err) {
    console.error("Error in /v1/check_email:", err);
    res.status(500).json({ error: "internal error" });
  }
});

// ============================================================================
// FILE CHECK (SCREENSHOTS + PDFs) — your original logic preserved
// ============================================================================

app.post("/v1/check_file", authAndMeter, async (req, res) => {
  try {
    const { content_base64, mime_type, filename, source, client_id } =
      req.body || {};

    if (!content_base64) {
      return res.status(400).json({ error: "missing content_base64" });
    }

    const base64 = content_base64.includes(",")
      ? content_base64.split(",")[1]
      : content_base64;

    const buffer = Buffer.from(base64, "base64");

    const mime = await detectMime(buffer, mime_type);

    if (!mime.startsWith("image/") && mime !== "application/pdf") {
      return res.status(400).json({ error: `unsupported file type ${mime}` });
    }

    const text = await extractTextFromBuffer(buffer, mime);

    if (!text || !text.trim()) {
      const response = {
        verdict: "suspicious",
        confidence: 0.5,
        evidence: ["file text could not be extracted"],
        next_steps: [
          "verify sender using a known official contact",
          "do not send money or codes based on this file alone"
        ],
        meta: {
          provider: "ocr",
          mime_type: mime,
          filename: filename || null,
          source: source || null,
          client_id: client_id || null
        },
        scan_id: `file_${Date.now().toString(36)}`
      };

      await db.query(
        `INSERT INTO scans
         (input_type, content_excerpt, file_name, mime_type,
          api_key, day_count, total_count,
          verdict, confidence, evidence, next_steps, meta)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          "file",
          null,
          filename || null,
          mime,
          req.apiKey,
          req.apiUsage?.dayCount ?? null,
          req.apiUsage?.total ?? null,
          response.verdict,
          response.confidence,
          JSON.stringify(response.evidence),
          JSON.stringify(response.next_steps),
          JSON.stringify(response.meta)
        ]
      );

      return res.json(response);
    }

    const urls = extractUrlsFromText(text);

    if (urls.length > 0) {
      const primaryUrl = urls[0];

      const ipqsResult = await ipqsUrlCheck(primaryUrl, { strictness: 1 });

      const response = {
        ...(ipqsResult.error
          ? {
              verdict: "suspicious",
              confidence: 0.6,
              evidence: [
                `URL detected in document: ${primaryUrl}`,
                `IPQS lookup failed: ${ipqsResult.error}`
              ],
              next_steps: [
                "verify sender independently",
                "do not click links",
                "open the official website manually"
              ],
              meta: {
                provider: "ocr",
                mime_type: mime,
                filename: filename || null,
                extracted_url_count: urls.length,
                source: source || null,
                client_id: client_id || null
              }
            }
          : {
              ...ipqsResult,
              evidence: [
                `file type ${mime}`,
                `URL extracted: ${primaryUrl}`,
                ...(ipqsResult.evidence || [])
              ],
              meta: {
                ...(ipqsResult.meta || {}),
                provider: "ocr+ipqs",
                mime_type: mime,
                filename: filename || null,
                extracted_url_count: urls.length,
                source: source || null,
                client_id: client_id || null
              }
            }),
        scan_id: `file_${Date.now().toString(36)}`
      };

      await db.query(
        `INSERT INTO scans
         (input_type, content_excerpt, file_name, mime_type,
          api_key, day_count, total_count,
          verdict, confidence, evidence, next_steps, meta)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          "file",
          text.slice(0, 200),
          filename || null,
          mime,
          req.apiKey,
          req.apiUsage?.dayCount ?? null,
          req.apiUsage?.total ?? null,
          response.verdict,
          response.confidence,
          JSON.stringify(response.evidence),
          JSON.stringify(response.next_steps),
          JSON.stringify(response.meta)
        ]
      );

      return res.json(response);
    }

    // Fallback: heuristic scan with no URLs
    const lower = text.toLowerCase();
    const evidence = [`file type ${mime}`, "no URLs detected"];
    let verdict = "safe";
    let confidence = 0.7;

    if (
      lower.includes("wire transfer") ||
      lower.includes("gift card") ||
      lower.includes("urgent")
    ) {
      verdict = "likely_scam";
      confidence = 0.92;
      evidence.push("financial or urgency keywords detected");
    } else if (
      lower.includes("login") ||
      lower.includes("password") ||
      lower.includes("verify account")
    ) {
      verdict = "suspicious";
      confidence = 0.8;
      evidence.push("credential-related keywords detected");
    }

    const response = {
      verdict,
      confidence,
      evidence,
      next_steps:
        verdict === "likely_scam"
          ? [
              "do not follow payment instructions",
              "verify with sender independently",
              "retain a copy for reporting"
            ]
          : [
              "verify any payment or login request independently",
              "do not share one time codes"
            ],
      meta: {
        provider: "ocr",
        mime_type: mime,
        filename: filename || null,
        source: source || null,
        client_id: client_id || null
      },
      scan_id: `file_${Date.now().toString(36)}`
    };

    await db.query(
      `INSERT INTO scans
       (input_type, content_excerpt, file_name, mime_type,
        api_key, day_count, total_count,
        verdict, confidence, evidence, next_steps, meta)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        "file",
        text.slice(0, 200),
        filename || null,
        mime,
        req.apiKey,
        req.apiUsage?.dayCount ?? null,
        req.apiUsage?.total ?? null,
        response.verdict,
        response.confidence,
        JSON.stringify(response.evidence),
        JSON.stringify(response.next_steps),
        JSON.stringify(response.meta)
      ]
    );

    res.json(response);
  } catch (err) {
    console.error("Error in /v1/check_file:", err);
    res.status(500).json({ error: "internal error in file scanner" });
  }
});

// ============================================================================
// ADMIN ROUTE (unchanged)
// ============================================================================

// keep the entire admin block from your original file here

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log(`ScamDefender API listening on port ${PORT}`);
});