import { request } from "undici";

const IPQS_KEY = process.env.IPQS_KEY;
if (!IPQS_KEY) {
  throw new Error("Missing IPQS_KEY environment variable");
}

function scoreToVerdict(score, flags = {}) {
  if (flags.phishing || flags.malware || flags.unsafe) return { verdict: "likely_scam", confidence: 0.95 };
  if (score >= 75) return { verdict: "likely_scam", confidence: Math.min(0.9, 0.6 + score / 100) };
  if (score >= 40 || flags.suspicious || flags.disposable === true || flags.valid === false) {
    return { verdict: "suspicious", confidence: Math.min(0.85, 0.5 + score / 100) };
  }
  return { verdict: "safe", confidence: Math.max(0.6, 1 - score / 150) };
}

export async function ipqsEmailCheck(email, { timeout = 7, fast = false, abuse_strictness = 1 } = {}) {
  const url = new URL(`https://www.ipqualityscore.com/api/json/email/${IPQS_KEY}/${encodeURIComponent(email)}`);
  url.searchParams.set("timeout", String(timeout));
  url.searchParams.set("fast", String(fast));
  url.searchParams.set("abuse_strictness", String(abuse_strictness));

  const res = await request(url.toString(), { method: "GET" });
  const data = await res.body.json();

  if (data.success === false) {
    return { error: data.message || "IPQS email lookup failed", raw: data };
  }

  const ev = [];
  if (data.deliverability) ev.push(`deliverability ${data.deliverability}`);
  if (data.disposable) ev.push("disposable email service");
  if (data.dns_valid === false) ev.push("domain DNS invalid");
  if (data.mx_records && data.mx_records.length) ev.push("MX records present");
  if (data.spam_trap_score && data.spam_trap_score !== "none") ev.push(`spam trap score ${data.spam_trap_score}`);
  if (data.first_seen?.human) ev.push(`email first seen ${data.first_seen.human}`);
  if (data.domain_age?.human) ev.push(`domain age ${data.domain_age.human}`);
  if (data.recent_abuse) ev.push("recent abuse signals");
  if (typeof data.fraud_score === "number") ev.push(`fraud_score ${data.fraud_score}`);

  const flags = { suspicious: data.suspect, disposable: data.disposable, valid: data.valid, phishing: false, malware: false, unsafe: false };
  const mapped = scoreToVerdict(data.fraud_score ?? 0, flags);

  return {
    verdict: mapped.verdict,
    confidence: mapped.confidence,
    evidence: ev,
    next_steps: mapped.verdict === "likely_scam"
      ? ["do not reply", "verify sender on an official site", "report to provider"]
      : mapped.verdict === "suspicious"
      ? ["verify sender by another channel", "avoid clicking links", "be cautious with attachments"]
      : ["no high risk issues found", "stay vigilant"],
    meta: { provider: "ipqs", risk_score: data.fraud_score, request_id: data.request_id }
  };
}

export async function ipqsUrlCheck(rawUrl, { strictness = 1, fast = false } = {}) {
  const url = new URL(`https://www.ipqualityscore.com/api/json/url/${IPQS_KEY}/${encodeURIComponent(rawUrl)}`);
  url.searchParams.set("strictness", String(strictness));
  url.searchParams.set("fast", String(fast));
  url.searchParams.set("timeout", "7");

  const res = await request(url.toString(), { method: "GET" });
  const data = await res.body.json();

  if (data.success === false) {
    return { error: data.message || "IPQS URL lookup failed", raw: data };
  }

  const ev = [];
  if (typeof data.risk_score === "number") ev.push(`risk_score ${data.risk_score}`);
  if (data.phishing) ev.push("phishing detected");
  if (data.malware) ev.push("malware detected");
  if (data.suspicious) ev.push("suspicious behavior");
  if (data.parking) ev.push("parked domain");
  if (data.risky_tld) ev.push("risky TLD");
  if (data.domain_age?.human) ev.push(`domain age ${data.domain_age.human}`);
  if (data.redirected) ev.push("redirect chain present");
  if (data.category) ev.push(`category ${data.category}`);

  const flags = { phishing: data.phishing, malware: data.malware, suspicious: data.suspicious, unsafe: data.unsafe };
  const mapped = scoreToVerdict(data.risk_score ?? 0, flags);

  return {
    verdict: mapped.verdict,
    confidence: mapped.confidence,
    evidence: ev,
    next_steps: mapped.verdict === "likely_scam"
      ? ["do not click", "open the known official site instead", "report the link"]
      : mapped.verdict === "suspicious"
      ? ["hover to inspect the domain", "avoid submitting credentials", "verify with the sender"]
      : ["no high risk issues found", "use caution"],
    meta: { provider: "ipqs", risk_score: data.risk_score, request_id: data.request_id, final_url: data.final_url }
  };
}
