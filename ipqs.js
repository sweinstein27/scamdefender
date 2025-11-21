// ipqs.js
import fetch from "node-fetch";

const IPQS_API_KEY = process.env.IPQS_API_KEY;

// ---------------------------------------------------------------------------
// Map IPQS raw response to ScamDefender verdict
// You already had this logic. We keep it to ensure extension + website match.
// ---------------------------------------------------------------------------
function mapIpqsToVerdict(ipqs) {
  const fraudScore = Number(ipqs.fraud_score || ipqs.risk_score || 0);

  if (fraudScore >= 85) {
    return {
      verdict: "likely_scam",
      confidence: 0.95
    };
  }

  if (fraudScore >= 50) {
    return {
      verdict: "suspicious",
      confidence: 0.8
    };
  }

  return {
    verdict: "safe",
    confidence: 0.7
  };
}

// ---------------------------------------------------------------------------
// Safe fetch wrapper so HTML responses or IPQS outages don't crash your API
// ---------------------------------------------------------------------------
async function safeFetchJson(url) {
  const resp = await fetch(url);

  const text = await resp.text();

  try {
    return JSON.parse(text);
  } catch (err) {
    console.error("IPQS returned non-JSON response:", text.slice(0, 500));
    throw new Error("IPQS_INVALID_JSON");
  }
}

// ---------------------------------------------------------------------------
// URL CHECK
// Correct endpoint: https://ipqualityscore.com/api/json/url/YOUR_KEY?url=...
// ---------------------------------------------------------------------------
export async function ipqsUrlCheck(content, options = {}) {
  if (!IPQS_API_KEY) {
    throw new Error("Missing IPQS_API_KEY");
  }

  const strictness = options.strictness || 1;

  const params = new URLSearchParams({
    url: content,
    strictness: String(strictness),
    fast: "true"
  });

  const endpoint =
    `https://ipqualityscore.com/api/json/url/${IPQS_API_KEY}?` +
    params.toString();

  let data;
  try {
    data = await safeFetchJson(endpoint);
  } catch (err) {
    console.error("ipqsUrlCheck failed:", err);

    // fallback result when IPQS fails
    return {
      verdict: "suspicious",
      confidence: 0.6,
      evidence: [`IPQS URL lookup failed`],
      next_steps: [
        "verify the sender independently",
        "avoid clicking links until verified",
        "open the official website manually"
      ],
      meta: {
        provider: "ipqs",
        error: String(err)
      }
    };
  }

  const { verdict, confidence } = mapIpqsToVerdict(data);

  return {
    verdict,
    confidence,
    evidence: [
      `IPQS fraud score ${data.fraud_score}`,
      `IPQS suspicious: ${data.suspicious}`
    ],
    next_steps: [
      "do not share codes or passwords",
      "verify the sender on an official website"
    ],
    meta: {
      provider: "ipqs",
      raw: data
    }
  };
}

// ---------------------------------------------------------------------------
// EMAIL CHECK
// Correct endpoint: https://ipqualityscore.com/api/json/email/YOUR_KEY?email=...
// ---------------------------------------------------------------------------
export async function ipqsEmailCheck(email, options = {}) {
  if (!IPQS_API_KEY) {
    throw new Error("Missing IPQS_API_KEY");
  }

  const strictness = options.strictness || 1;

  const params = new URLSearchParams({
    email,
    strictness: String(strictness),
    fast: "true"
  });

  const endpoint =
    `https://ipqualityscore.com/api/json/email/${IPQS_API_KEY}?` +
    params.toString();

  let data;
  try {
    data = await safeFetchJson(endpoint);
  } catch (err) {
    console.error("ipqsEmailCheck failed:", err);

    return {
      verdict: "suspicious",
      confidence: 0.6,
      evidence: [`IPQS email lookup failed`],
      next_steps: [
        "be cautious sharing financial information",
        "verify the sender manually"
      ],
      meta: {
        provider: "ipqs",
        error: String(err)
      }
    };
  }

  const { verdict, confidence } = mapIpqsToVerdict(data);

  return {
    verdict,
    confidence,
    evidence: [
      `IPQS fraud score ${data.fraud_score}`,
      `IPQS valid: ${data.valid}`
    ],
    next_steps: [
      "look for misspellings or urgency cues",
      "verify the sender independently"
    ],
    meta: {
      provider: "ipqs",
      raw: data
    }
  };
}