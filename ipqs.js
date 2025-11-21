// ipqs.js
import fetch from "node-fetch";

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

export async function ipqsUrlCheck(content, options = {}) {
  const resp = await fetch("https://ipqualityscore.com/api/url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: content, strictness: options.strictness || 1 })
  });

  const data = await resp.json();

  const { verdict, confidence } = mapIpqsToVerdict(data);

  return {
    verdict,
    confidence,
    evidence: [
      `ipqs fraud score ${data.fraud_score}`,
      `ipqs suspicious flag ${data.suspicious}`
    ],
    next_steps: [
      "do not share codes or passwords",
      "verify sender on an official site"
    ],
    meta: {
      provider: "ipqs",
      raw: data
    }
  };
}

export async function ipqsEmailCheck(email, options = {}) {
  const resp = await fetch("https://ipqualityscore.com/api/email", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, strictness: options.strictness || 1 })
  });

  const data = await resp.json();

  const { verdict, confidence } = mapIpqsToVerdict(data);

  return {
    verdict,
    confidence,
    evidence: [
      `ipqs fraud score ${data.fraud_score}`,
      `ipqs valid flag ${data.valid}`
    ],
    next_steps: [
      "be cautious sharing financial details",
      "watch for spelling errors and urgency"
    ],
    meta: {
      provider: "ipqs",
      raw: data
    }
  };
}