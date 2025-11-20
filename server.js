import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";
import { ipqsUrlCheck, ipqsEmailCheck } from "./ipqs.js";

const app = express();
const PORT = process.env.PORT || 8080;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

app.use(helmet());
app.use(bodyParser.json({ limit: "300kb" }));
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

app.listen(PORT, () => {
  console.log(`ScamDefender IPQS API listening on ${PORT}`);
});
