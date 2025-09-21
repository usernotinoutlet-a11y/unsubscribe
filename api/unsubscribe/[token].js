// api/unsubscribe/[token].js
import crypto from "crypto";
import pg from "pg";
const { Pool } = pg;

// -------------------- ENV --------------------
const UNSUB_SECRET =
  process.env.UNSUB_SECRET ||
  "CHANGE_THIS_SECRET"; // set a real secret in Vercel
const DATABASE_URL = process.env.DATABASE_URL;

// Leave this EMPTY in Vercel to show the inline page on GET.
// If you set a URL here (e.g. https://notinoutletnl.com/unsubscribe-page),
// GET clicks will 302 there instead.
const VISIBLE_UNSUB_REDIRECT = process.env.VISIBLE_UNSUB_REDIRECT || "";

// -------------------- DB POOL --------------------
let pool = globalThis.__unsub_pool;
if (!pool && DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 1,
  });
  globalThis.__unsub_pool = pool;
}

// -------------------- HELPERS --------------------
function base64urlToBuffer(b64url) {
  const rem = b64url.length % 4;
  const pad = rem ? 4 - rem : 0;
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(b64, "base64");
}

function safeEqual(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (m) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m])
  );
}

function maskEmail(email) {
  const [local, domain] = String(email).split("@");
  if (!domain) return email;
  if (local.length <= 2) return `${local[0] || ""}***@${domain}`;
  return `${local.slice(0, 2)}***@${domain}`;
}

async function saveSuppression(email, source) {
  if (!pool) return; // no DB configured; don't block UX
  await pool.query(
    `CREATE TABLE IF NOT EXISTS suppression (
       email  TEXT PRIMARY KEY,
       source TEXT NOT NULL,
       reason TEXT NOT NULL,
       ts     TIMESTAMPTZ NOT NULL DEFAULT now()
     );`
  );
  await pool.query(
    `INSERT INTO suppression (email, source, reason)
     VALUES ($1, $2, 'user-request')
     ON CONFLICT (email) DO UPDATE
       SET source = EXCLUDED.source,
           reason = EXCLUDED.reason,
           ts     = now()`,
    [email, source]
  );
}

// -------------------- HANDLER --------------------
export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, max-age=0");

  if (req.method !== "GET" && req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).end("Method Not Allowed");
  }

  const token = Array.isArray(req.query.token)
    ? req.query.token[0]
    : req.query.token;

  if (!token || typeof token !== "string") {
    return res.status(400).send("missing token");
  }

  // ---- Robust token split: [JSON][.][HMAC(32 bytes)] ----
  let raw, sig;
  try {
    const buf = base64urlToBuffer(token);
    if (buf.length < 33) throw new Error("bad token");
    sig = buf.subarray(buf.length - 32);
    const sep = buf[buf.length - 33];
    if (sep !== 46) throw new Error("bad token"); // 46 = '.'
    raw = buf.subarray(0, buf.length - 33);
  } catch {
    return res.status(400).send("bad token");
  }

  // Verify signature
  const expected = crypto.createHmac("sha256", UNSUB_SECRET).update(raw).digest();
  if (!safeEqual(expected, sig)) {
    return res.status(400).send("signature");
  }

  // Parse payload
  let payload;
  try {
    payload = JSON.parse(raw.toString("utf8"));
  } catch {
    return res.status(400).send("payload");
  }

  if (!payload.email || !payload.exp) {
    return res.status(400).send("payload");
  }
  if (Date.now() / 1000 > Number(payload.exp)) {
    return res.status(400).send("expired");
  }

  const email = String(payload.email).trim().toLowerCase();

  // Save suppression; POST = one-click, GET = human click
  try {
    await saveSuppression(email, req.method === "POST" ? "one-click" : "web");
  } catch (e) {
    console.error("suppression save failed:", e);
  }

  // POST must be 204 for one-click
  if (req.method === "POST") {
    return res.status(204).end();
  }

  // Human flow
  const masked = maskEmail(email);

  if (VISIBLE_UNSUB_REDIRECT) {
    const url = new URL(VISIBLE_UNSUB_REDIRECT);
    url.searchParams.set("status", "success");
    url.searchParams.set("email", masked);
    res.setHeader("Location", url.toString());
    return res.status(302).end();
  }

  // Inline branded confirmation page
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Unsubscribe • NotinoutletNL</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    html,body{margin:0;padding:0;background:#f6f7f9;color:#111;font-family:Arial,Helvetica,sans-serif}
    .wrap{max-width:720px;margin:40px auto;padding:24px}
    .card{background:#fff;border-radius:16px;box-shadow:0 6px 18px rgba(0,0,0,.06);padding:28px}
    h1{font-size:28px;margin:0 0 8px}
    p{margin:8px 0 0;line-height:1.5}
    .ok{display:inline-flex;align-items:center;justify-content:center;
        width:36px;height:36px;border-radius:999px;background:#e8f7ec;margin-right:10px}
    .ok::after{content:"✓";font-weight:700}
    .muted{color:#6b7280;font-size:12px;margin-top:16px}
    .actions{margin-top:20px;display:flex;gap:10px;flex-wrap:wrap}
    .btn{display:inline-block;padding:12px 16px;border-radius:10px;text-decoration:none}
    .btn-primary{background:#0ea5e9;color:#fff}
    .btn-outline{border:1px solid #e5e7eb;color:#111;background:#fff}
    .brand{font-weight:700;letter-spacing:.3px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div style="display:flex;align-items:center;margin-bottom:6px">
        <span class="ok"></span>
        <div class="brand">NotinoutletNL</div>
      </div>
      <h1>You're unsubscribed</h1>
      <p>You will no longer receive marketing emails from <strong>NotinoutletNL</strong> at <strong>${esc(maskEmail(email))}</strong>.</p>
      <div class="actions">
        <a class="btn btn-primary" href="https://notinoutletnl.com">Return to Homepage</a>
        <a class="btn btn-outline" href="mailto:info@notinoutletnl.com?subject=Unsubscribe%20Help">Contact Support</a>
      </div>
      <p class="muted">If this was a mistake, reply to any previous email and we'll re-add you.</p>
    </div>
  </div>
</body>
</html>`);
}
