import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";
import cors from "cors";
import pg from "pg";

import { ipqsUrlCheck, ipqsEmailCheck } from "./ipqs.js";
import { detectMime, extractTextFromBuffer, extractUrlsFromText } from "./ocr.js";
import authRoutes from "./routes/auth.js";
app.use("/auth", authRoutes);

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
// Admin dashboard (password protected, internal use only)
// -----------------------------------------------------------------------------

app.get("/admin", async (req, res) => {
  try {
    const adminPassword = process.env.ADMIN_PASSWORD;
    const token = req.query.p;

    if (!adminPassword) {
      return res
        .status(500)
        .send("ADMIN_PASSWORD is not configured on the server.");
    }

    if (!token || token !== adminPassword) {
      return res
        .status(401)
        .send("Unauthorized. Append ?p=ADMIN_PASSWORD to the URL.");
    }

    // 1) Daily stats (last 30 days)
    const dailyRes = await db.query(
      `SELECT
         DATE(created_at) AS day,
         COUNT(*) AS total_scans,
         COUNT(*) FILTER (WHERE verdict = 'safe') AS safe,
         COUNT(*) FILTER (WHERE verdict = 'suspicious') AS suspicious,
         COUNT(*) FILTER (WHERE verdict = 'likely_scam') AS likely_scam
       FROM scans
       GROUP BY 1
       ORDER BY 1 DESC
       LIMIT 30`
    );

    // 2) Verdict distribution
    const verdictRes = await db.query(
      `SELECT verdict, COUNT(*) AS count
       FROM scans
       GROUP BY verdict
       ORDER BY count DESC`
    );

    // 3) Input type distribution
    const typeRes = await db.query(
      `SELECT input_type, COUNT(*) AS count
       FROM scans
       GROUP BY input_type
       ORDER BY count DESC`
    );

    // 4) Top domains (from content_excerpt for url scans)
    const domainRes = await db.query(
      `SELECT
         LOWER(
           regexp_replace(
             regexp_replace(content_excerpt, '^https?://', ''),
             '/.*$', ''
           )
         ) AS domain,
         COUNT(*) AS count
       FROM scans
       WHERE input_type IN ('url', 'text')
         AND content_excerpt IS NOT NULL
       GROUP BY domain
       HAVING COUNT(*) >= 2
       ORDER BY count DESC
       LIMIT 10`
    );

    // 5) Recent scans
    const recentRes = await db.query(
      `SELECT
         created_at,
         input_type,
         verdict,
         confidence,
         api_key,
         content_excerpt
       FROM scans
       ORDER BY created_at DESC
       LIMIT 50`
    );

    const dailyRows = dailyRes.rows.reverse(); // oldest first for chart
    const verdictRows = verdictRes.rows;
    const typeRows = typeRes.rows;
    const domainRows = domainRes.rows;
    const recentRows = recentRes.rows;

    const dailyLabels = dailyRows.map(r => r.day);
    const dailyTotals = dailyRows.map(r => Number(r.total_scans || 0));

    const verdictLabels = verdictRows.map(r => r.verdict || "unknown");
    const verdictCounts = verdictRows.map(r => Number(r.count || 0));

    const typeLabels = typeRows.map(r => r.input_type || "unknown");
    const typeCounts = typeRows.map(r => Number(r.count || 0));

    const encode = JSON.stringify;

    const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>ScamDefender Admin</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 0;
      background: #0f172a;
      color: #e5e7eb;
    }
    .shell {
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px 16px 40px;
    }
    h1 {
      font-size: 26px;
      margin-bottom: 4px;
    }
    h2 {
      font-size: 18px;
      margin: 16px 0 8px;
    }
    .sub {
      color: #9ca3af;
      font-size: 13px;
      margin-bottom: 24px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .card {
      background: #020617;
      border-radius: 12px;
      padding: 12px 14px;
      border: 1px solid rgba(148, 163, 184, 0.35);
      box-shadow: 0 6px 16px rgba(15, 23, 42, 0.6);
    }
    .card h3 {
      font-size: 13px;
      margin: 0 0 6px;
      color: #9ca3af;
    }
    .card .value {
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 2px;
    }
    .card .hint {
      font-size: 11px;
      color: #6b7280;
    }
    .charts {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 16px;
      margin-bottom: 24px;
    }
    canvas {
      background: #020617;
      border-radius: 12px;
      padding: 12px;
      box-sizing: border-box;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    th, td {
      border-bottom: 1px solid rgba(55, 65, 81, 0.8);
      padding: 6px 8px;
      text-align: left;
    }
    th {
      color: #9ca3af;
      font-weight: 500;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      background: #020617;
    }
    tr:nth-child(even) td {
      background: rgba(15, 23, 42, 0.8);
    }
    .pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 500;
    }
    .pill-safe {
      background: rgba(22, 163, 74, 0.15);
      color: #4ade80;
    }
    .pill-suspicious {
      background: rgba(234, 179, 8, 0.15);
      color: #facc15;
    }
    .pill-likely_scam {
      background: rgba(239, 68, 68, 0.18);
      color: #fca5a5;
    }
    .pill-unknown {
      background: rgba(148, 163, 184, 0.2);
      color: #e5e7eb;
    }
    .muted {
      color: #9ca3af;
    }
    .nowrap {
      white-space: nowrap;
    }
    .excerpt {
      max-width: 320px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
  </style>
</head>
<body>
  <div class="shell">
    <h1>ScamDefender Admin</h1>
    <div class="sub">Internal dashboard for scans and verdicts. Protected by ADMIN_PASSWORD.</div>

    <div class="grid">
      <div class="card">
        <h3>Scans (last 24 hours)</h3>
        <div class="value">${
          dailyRows.length ? dailyRows[dailyRows.length - 1].total_scans : 0
        }</div>
        <div class="hint">From all sources and API keys</div>
      </div>
      <div class="card">
        <h3>Scans (last 7 days)</h3>
        <div class="value">${
          dailyRows.slice(-7).reduce((sum, r) => sum + Number(r.total_scans || 0), 0)
        }</div>
        <div class="hint">Rolling seven day total</div>
      </div>
      <div class="card">
        <h3>Unique API keys (all time)</h3>
        <div class="value">${
          new Set(recentRows.map(r => r.api_key).filter(Boolean)).size
        }</div>
        <div class="hint">Based on recent scan window</div>
      </div>
    </div>

    <div class="charts">
      <div>
        <h2>Daily scans</h2>
        <canvas id="dailyChart" height="180"></canvas>
      </div>
      <div>
        <h2>Verdicts</h2>
        <canvas id="verdictChart" height="180"></canvas>
      </div>
    </div>

    <div class="grid" style="grid-template-columns: 1.4fr 1fr;">
      <div class="card">
        <h3>Scans by input type</h3>
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            ${
              typeRows.length
                ? typeRows
                    .map(
                      r => `
              <tr>
                <td>${r.input_type || "unknown"}</td>
                <td>${r.count}</td>
              </tr>`
                    )
                    .join("")
                : `<tr><td colspan="2" class="muted">No data yet</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div class="card">
        <h3>Top domains (suspicious surface)</h3>
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Scans</th>
            </tr>
          </thead>
          <tbody>
            ${
              domainRows.length
                ? domainRows
                    .map(
                      r => `
              <tr>
                <td>${r.domain}</td>
                <td>${r.count}</td>
              </tr>`
                    )
                    .join("")
                : `<tr><td colspan="2" class="muted">Insufficient URL data</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>

    <h2>Recent scans</h2>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th class="nowrap">Time</th>
            <th>Type</th>
            <th>Verdict</th>
            <th>Conf</th>
            <th>API key</th>
            <th>Excerpt</th>
          </tr>
        </thead>
        <tbody>
          ${
            recentRows.length
              ? recentRows
                  .map(r => {
                    const verdict = r.verdict || "unknown";
                    const pillClass =
                      verdict === "safe"
                        ? "pill-safe"
                        : verdict === "suspicious"
                        ? "pill-suspicious"
                        : verdict === "likely_scam"
                        ? "pill-likely_scam"
                        : "pill-unknown";
                    const conf =
                      typeof r.confidence === "number"
                        ? Math.round(r.confidence * 100) + "%"
                        : "n/a";
                    const ts = new Date(r.created_at).toISOString().replace("T", " ").slice(0, 16);
                    const excerpt = (r.content_excerpt || "").replace(/\\s+/g, " ").slice(0, 120);
                    const keyLabel = r.api_key ? r.api_key : "n/a";
                    return `
              <tr>
                <td class="nowrap">${ts}</td>
                <td>${r.input_type || ""}</td>
                <td><span class="pill ${pillClass}">${verdict.replace("_", " ")}</span></td>
                <td>${conf}</td>
                <td class="muted">${keyLabel}</td>
                <td class="excerpt" title="${excerpt}">${excerpt}</td>
              </tr>`;
                  })
                  .join("")
              : `<tr><td colspan="6" class="muted">No scans logged yet</td></tr>`
          }
        </tbody>
      </table>
    </div>
  </div>

  <script>
    const dailyLabels = ${encode(dailyLabels)};
    const dailyTotals = ${encode(dailyTotals)};
    const verdictLabels = ${encode(verdictLabels)};
    const verdictCounts = ${encode(verdictCounts)};

    const dailyCtx = document.getElementById("dailyChart");
    const verdictCtx = document.getElementById("verdictChart");

    if (dailyLabels.length && dailyCtx) {
      new Chart(dailyCtx, {
        type: "line",
        data: {
          labels: dailyLabels,
          datasets: [{
            label: "Scans per day",
            data: dailyTotals,
            tension: 0.25,
            borderWidth: 2,
            pointRadius: 2
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              ticks: { color: "#9ca3af", maxRotation: 0, autoSkip: true },
              grid: { color: "rgba(55,65,81,0.4)" }
            },
            y: {
              ticks: { color: "#9ca3af" },
              grid: { color: "rgba(55,65,81,0.4)" }
            }
          }
        }
      });
    }

    if (verdictLabels.length && verdictCtx) {
      new Chart(verdictCtx, {
        type: "doughnut",
        data: {
          labels: verdictLabels,
          datasets: [{
            data: verdictCounts,
            borderWidth: 1
          }]
        },
        options: {
          plugins: {
            legend: {
              position: "bottom",
              labels: { color: "#e5e7eb", boxWidth: 12 }
            }
          },
          cutout: "60%"
        }
      });
    }
  </script>
</body>
</html>
`;

    res.send(html);
  } catch (err) {
    console.error("Error in /admin:", err);
    res.status(500).send("Internal error in admin dashboard.");
  }
});
// -----------------------------------------------------------------------------
// Start server
// -----------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`ScamDefender IPQS API listening on ${PORT}`);
});