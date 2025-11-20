import { detectMime, extractTextFromBuffer, extractUrlsFromText } from "./ocr.js";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";
import { ipqsUrlCheck, ipqsEmailCheck } from "./ipqs.js";

const app = express();
const PORT = process.env.PORT || 8080;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

app.use(helmet());
app.use(bodyParser.json({ limit: "5mb" }));
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

app.get("/healthz", (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.post("/v1/check", async (req, res) => {
  try {
    const { input_type, content } = req.body || {};
    if (!input_type || !content) return res.status(400).json({ error: "missing input_type or content" });

    if (input_type === "url") {
      const r = await ipqsUrlCheck(content, { strictness: 1 });
      if (r.error) return res.status(502).json({ error: r.error });
      return res.json({ ...r, scan_id: `url_${Date.now().toString(36)}` });
    }

    if (input_type === "text") {
      const m = content.match(/https?:\/\/\S+/);
      if (m) {
        const r = await ipqsUrlCheck(m[0], { strictness: 1 });
        if (r.error) return res.status(502).json({ error: r.error });
        return res.json({ ...r, scan_id: `txt_${Date.now().toString(36)}` });
      }
      return res.json({
        verdict: "suspicious",
        confidence: 0.55,
        evidence: ["no link present to scan", "content only scan uses local heuristics"],
        next_steps: ["avoid sending money or codes", "verify sender by a known channel"],
        scan_id: `txt_${Date.now().toString(36)}`
      });
    }

    return res.status(400).json({ error: "unsupported input_type for this endpoint" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal error" });
  }
});

app.post("/v1/check_email", async (req, res) => {
  try {
    const { content } = req.body || {};
    if (!content) return res.status(400).json({ error: "missing email" });
    const r = await ipqsEmailCheck(content, { timeout: 7, abuse_strictness: 1 });
    if (r.error) return res.status(502).json({ error: r.error });
    return res.json({ ...r, scan_id: `em_${Date.now().toString(36)}` });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal error" });
  }
});
app.post("/v1/check_file", async (req, res) => {
  try {
    const { content_base64, mime_type, filename } = req.body || {};
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

    if (!text.trim()) {
      return res.status(200).json({
        verdict: "suspicious",
        confidence: 0.5,
        evidence: ["file text could not be extracted"],
        next_steps: [
          "verify sender using a known official contact",
          "do not send money or codes based on this file alone"
        ],
        meta: { provider: "ocr", mime_type: mime, filename: filename || null },
        scan_id: `file_${Date.now().toString(36)}`
      });
    }

    const urls = extractUrlsFromText(text);

    if (urls.length > 0) {
      const primaryUrl = urls[0];
      const r = await ipqsUrlCheck(primaryUrl, { strictness: 1 });

      if (r.error) {
        return res.status(200).json({
          verdict: "suspicious",
          confidence: 0.6,
          evidence: [
            `URL detected: ${primaryUrl}`,
            `IPQS lookup failed: ${r.error}`
          ],
          next_steps: [
            "verify sender independently",
            "do not click links",
            "contact the official support number"
          ],
          meta: { provider: "ocr", mime_type: mime, filename },
          scan_id: `file_${Date.now().toString(36)}`
        });
      }

      return res.status(200).json({
        ...r,
        evidence: [
          `file type ${mime}`,
          `primary URL extracted: ${primaryUrl}`,
          ...(r.evidence || [])
        ],
        meta: {
          ...(r.meta || {}),
          provider: "ocr+ipqs",
          mime_type: mime,
          filename,
          extracted_url_count: urls.length
        },
        scan_id: `file_${Date.now().toString(36)}`
      });
    }

    let verdict = "safe";
    let confidence = 0.7;
    const lower = text.toLowerCase();
    const evidence = [`file type ${mime}`, "no URLs detected"];

    if (lower.includes("wire transfer") || lower.includes("urgent")) {
      verdict = "likely_scam";
      confidence = 0.92;
      evidence.push("payment or urgency language detected");
    } else if (lower.includes("password") || lower.includes("verify account")) {
      verdict = "suspicious";
      confidence = 0.8;
      evidence.push("credential harvesting language detected");
    }

    return res.status(200).json({
      verdict,
      confidence,
      evidence,
      next_steps: [
        "verify contact by official website",
        "do not make payments without confirmation"
      ],
      meta: { provider: "ocr", mime_type: mime, filename },
      scan_id: `file_${Date.now().toString(36)}`
    });
  } catch (e) {
    console.error("OCR error:", e);
    res.status(500).json({ error: "internal error in file scanner" });
  }
});
app.listen(PORT, () => {
  console.log(`ScamDefender IPQS API listening on ${PORT}`);
});
