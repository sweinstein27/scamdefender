import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";
import cors from "cors";
import pg from "pg";

import { ipqsUrlCheck, ipqsEmailCheck } from "./ipqs.js";
import { detectMime, extractTextFromBuffer, extractUrlsFromText } from "./ocr.js";

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

const PORT = process.env.PORT || 8080;

const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

const API_KEYS = (process.env.API_KEYS || "")
  .split(",")
  .map(k => k.trim())
  .filter(Boolean);

const FREE_DAILY_LIMIT = Number(process.env.FREE_DAILY_LIMIT || "500");

// Postgres
const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL
});

// In memory metering
const keyUsage = new Map(); // key -> { day, dayCount, total }

function todayString() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

// -----------------------------------------------------------------------------
// Auth and metering middleware
// -----------------------------------------------------------------------------

function authAndMeter(req, res, next) {
  // If no keys set, run open mode for now
  if (!API_KEYS.length) {
    return next();
  }

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
      total: usage && typeof usage.total === "number" ? usage.total : 0
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
  return next();
}

// -----------------------------------------------------------------------------
// Logging helper
// -----------------------------------------------------------------------------

async function logScan({
  input_type,
  content_excerpt,
  file_name,
  mime_type,
  api_key,
  usage,
  verdict,
  confidence,
  evidence,
  next_steps,
  meta
}) {
  try {
    await db.query(
      `INSERT INTO scans
       (input_type, content_excerpt, file_name, mime_type,
        api_key, day_count, total_count,
        verdict, confidence, evidence, next_steps, meta)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        input_type,
        content_excerpt || null,
        file_name || null,
        mime_type || null,
        api_key || null,
        usage?.dayCount || null,
        usage?.total || null,
        verdict || null,
        confidence ?? null,
        evidence ? JSON.stringify(evidence) : null,
        next_steps ? JSON.stringify(next_steps) : null,
        meta ? JSON.stringify(meta) : null
      ]
    );
  } catch (err) {
    console.error("Failed to log scan:", err);
  }
}

// -----------------------------------------------------------------------------
// Express app setup
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

app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? "*" : CORS_ORIGIN,
    credentials: false
  })
);

// Increase JSON body limit to handle base64 file uploads
app.use(bodyParser.json({ limit: "5mb" }));

// -----------------------------------------------------------------------------
// Health
// -----------------------------------------------------------------------------

app.get("/healthz", (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// -----------------------------------------------------------------------------
// URL and text check
// -----------------------------------------------------------------------------

app.post("/v1/check", authAndMeter, async (req, res) => {
  try {
    const { input_type = "url", content, source, client_id } = req.body || {};
    if (!content) {
      return res.status(400).json({ error: "missing content" });
    }

    // For now treat everything as a URL check when using IPQS
    const result = await ipqsUrlCheck(content, { strictness: 1 });

    await logScan({
      input_type,
      content_excerpt: String(content).slice(0, 200),
      file_name: null,
      mime_type: null,
      api_key: req.apiKey,
      usage: req.apiUsage,
      verdict: result.verdict,
      confidence: result.confidence,
      evidence: result.evidence,
      next_steps: result.next_steps,
      meta: {
        ...(result.meta || {}),
        source: source || null,
        client_id: client_id || null
      }
    });

    return res.json(result);
  } catch (err) {
    console.error("Error in /v1/check:", err);
    return res.status(500).json({ error: "internal error" });
  }
});

// -----------------------------------------------------------------------------
// Email check
// -----------------------------------------------------------------------------

app.post("/v1/check_email", authAndMeter, async (req, res) => {
  try {
    const { input_type = "email", content, source, client_id } = req.body || {};
    if (!content) {
      return res.status(400).json({ error: "missing content" });
    }

    const result = await ipqsEmailCheck(content, { strictness: 1 });

    await logScan({
      input_type,
      content_excerpt: String(content).slice(0, 200),
      file_name: null,
      mime_type: null,
      api_key: req.apiKey,
      usage: req.apiUsage,
      verdict: result.verdict,
      confidence: result.confidence,
      evidence: result.evidence,
      next_steps: result.next_steps,
      meta: {
        ...(result.meta || {}),
        source: source || null,
        client_id: client_id || null
      }
    });

    return res.json(result);
  } catch (err) {
    console.error("Error in /v1/check_email:", err);
    return res.status(500).json({ error: "internal error" });
  }
});

// -----------------------------------------------------------------------------
// File check (screenshots and PDFs)
// -----------------------------------------------------------------------------

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
      return res
        .status(400)
        .json({ error: `unsupported file type ${mime}` });
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

      await logScan({
        input_type: "file",
        content_excerpt: null,
        file_name: filename || null,
        mime_type: mime,
        api_key: req.apiKey,
        usage: req.apiUsage,
        verdict: response.verdict,
        confidence: response.confidence,
        evidence: response.evidence,
        next_steps: response.next_steps,
        meta: response.meta
      });

      return res.json(response);
    }

    const urls = extractUrlsFromText(text);

    // Case 1: URLs present, use IPQS URL check on the first one
    if (urls.length > 0) {
      const primaryUrl = urls[0];
      const ipqsResult = await ipqsUrlCheck(primaryUrl, { strictness: 1 });

      let response;

      if (ipqsResult.error) {
        response = {
          verdict: "suspicious",
          confidence: 0.6,
          evidence: [
            `URL detected in document: ${primaryUrl}`,
            `IPQS lookup failed: ${ipqsResult.error}`
          ],
          next_steps: [
            "verify sender independently",
            "do not click links",
            "open the official website by typing the address yourself"
          ],
          meta: {
            provider: "ocr",
            mime_type: mime,
            filename: filename || null,
            extracted_url_count: urls.length,
            source: source || null,
            client_id: client_id || null
          },
          scan_id: `file_${Date.now().toString(36)}`
        };
      } else {
        response = {
          ...ipqsResult,
          evidence: [
            `file type ${mime}`,
            `primary URL extracted from document: ${primaryUrl}`,
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
          },
          scan_id: `file_${Date.now().toString(36)}`
        };
      }

      await logScan({
        input_type: "file",
        content_excerpt: text.slice(0, 200),
        file_name: filename || null,
        mime_type: mime,
        api_key: req.apiKey,
        usage: req.apiUsage,
        verdict: response.verdict,
        confidence: response.confidence,
        evidence: response.evidence,
        next_steps: response.next_steps,
        meta: response.meta
      });

      return res.json(response);
    }

    // Case 2: no URLs, fall back to content heuristics
    const lower = text.toLowerCase();
    const evidence = [`file type ${mime}`, "no URLs detected in document"];
    let verdict = "safe";
    let confidence = 0.7;

    if (
      lower.includes("wire transfer") ||
      lower.includes("gift card") ||
      lower.includes("urgent")
    ) {
      verdict = "likely_scam";
      confidence = 0.92;
      evidence.push("payment or urgency language detected");
    } else if (
      lower.includes("login") ||
      lower.includes("password") ||
      lower.includes("verify account")
    ) {
      verdict = "suspicious";
      confidence = 0.8;
      evidence.push("credential or verification language detected");
    }

    const response = {
      verdict,
      confidence,
      evidence,
      next_steps:
        verdict === "likely_scam"
          ? [
              "do not follow payment instructions in this document",
              "verify with the sender using an independent contact",
              "keep a copy of this file for reporting if needed"
            ]
          : [
              "verify any payment or login requests by a known channel",
              "do not share one time codes or passwords"
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

    await logScan({
      input_type: "file",
      content_excerpt: text.slice(0, 200),
      file_name: filename || null,
      mime_type: mime,
      api_key: req.apiKey,
      usage: req.apiUsage,
      verdict: response.verdict,
      confidence: response.confidence,
      evidence: response.evidence,
      next_steps: response.next_steps,
      meta: response.meta
    });

    return res.json(response);
  } catch (err) {
    console.error("Error in /v1/check_file:", err);
    return res.status(500).json({ error: "internal error in file scanner" });
  }
});

// -----------------------------------------------------------------------------
// Start server
// -----------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`ScamDefender IPQS API listening on ${PORT}`);
});