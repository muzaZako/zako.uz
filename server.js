/* ============================================================
   ZAKO — backend (toza versiya)
   • Telegram login  — bir bosishda kirish, kriptografik imzo tekshiriladi
   • Telefon (zaxira) — telefon + parol (bcrypt), kodsiz
   • AI proxy         — OpenAI-mos (OpenRouter / Groq), kalit serverda qoladi
   • Xavfsizlik       — JWT, bcrypt, rate-limit (brute-force himoyasi)
   Render env: AI_API_KEY, AI_BASE_URL, AI_MODEL,
               TG_BOT_TOKEN, TG_BOT_USERNAME, JWT_SECRET
   Ishga tushirish:  npm install  &&  npm start
   ============================================================ */
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
try { require("dotenv").config(); } catch (e) {}

const app = express();
app.use(express.json({ limit: "8mb" }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "ALMASHTIRING-uzun-maxfiy-kalit";
const PAID_THRESHOLD = parseInt(process.env.PAID_THRESHOLD || "50", 10);

/* ---------- AI (OpenAI-mos: OpenRouter / Groq) ---------- */
const AI_PROVIDER = (process.env.AI_PROVIDER || "openai").toLowerCase();
const AI_KEY = process.env.AI_API_KEY || process.env.OPENROUTER_API_KEY || process.env.GROQ_API_KEY || "";
const AI_BASE = (process.env.AI_BASE_URL || "https://openrouter.ai/api/v1").replace(/\/+$/, "");
const AI_MODEL = process.env.AI_MODEL || "openrouter/free";

/* ---------- Telegram login ---------- */
const TG_BOT_TOKEN = process.env.TG_BOT_TOKEN || "";
const TG_BOT_USERNAME = (process.env.TG_BOT_USERNAME || "").replace(/^@/, "");

/* ---------- JSON ma'lumotlar bazasi ---------- */
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "users.json");
let users = [];
try { users = JSON.parse(fs.readFileSync(DB_FILE, "utf8")); } catch (e) { users = []; }
let saving = false, saveAgain = false;
function persist() {
  if (saving) { saveAgain = true; return; }
  saving = true;
  fs.writeFile(DB_FILE, JSON.stringify(users, null, 2), () => {
    saving = false;
    if (saveAgain) { saveAgain = false; persist(); }
  });
}

/* ---------- Rate-limit (brute-force himoyasi) ---------- */
const hits = {};
function rateOk(key, max, windowMs) {
  const now = Date.now();
  if (!hits[key] || now > hits[key].reset) hits[key] = { n: 0, reset: now + windowMs };
  hits[key].n++;
  return hits[key].n <= max;
}
function clientIp(req) { return String(req.headers["x-forwarded-for"] || req.ip || "ip").split(",")[0].trim(); }

/* ---------- Yordamchilar ---------- */
function makeToken(u) { return jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: "60d" }); }
function normPhone(v) { let d = (v || "").replace(/\D/g, ""); if (d.startsWith("998")) d = d.slice(3); return d.length === 9 ? "+998" + d : null; }
function textFromContent(c) {
  if (typeof c === "string") return c;
  if (Array.isArray(c)) return c.map(p => (p && p.type === "text") ? p.text : (typeof p === "string" ? p : "")).filter(Boolean).join("\n");
  return "";
}

/* ============================ TELEGRAM LOGIN ============================ */
// Telegram Login Widget ma'lumotini bot tokeni bilan tekshiradi (rasmiy algoritm)
function checkTelegramAuth(data) {
  if (!TG_BOT_TOKEN) return false;
  const hash = data.hash;
  const pairs = Object.keys(data).filter(k => k !== "hash" && data[k] != null).sort().map(k => k + "=" + data[k]);
  const checkString = pairs.join(String.fromCharCode(10));
  const secret = crypto.createHash("sha256").update(TG_BOT_TOKEN).digest();
  const hmac = crypto.createHmac("sha256", secret).update(checkString).digest("hex");
  return hmac === hash;
}
app.post("/api/tg-auth", (req, res) => {
  if (!rateOk("tg:" + clientIp(req), 20, 60000)) return res.status(429).json({ error: "Juda ko'p urinish, biroz kuting" });
  if (!TG_BOT_TOKEN) return res.status(500).json({ error: "Server Telegram sozlanmagan (TG_BOT_TOKEN)" });
  const data = req.body || {};
  if (!data.id || !data.hash) return res.status(400).json({ error: "Telegram ma'lumotlari to'liq emas" });
  if (!checkTelegramAuth(data)) return res.status(401).json({ error: "Telegram imzosi noto'g'ri" });
  if (data.auth_date && (Math.floor(Date.now() / 1000) - Number(data.auth_date) > 86400))
    return res.status(401).json({ error: "Telegram sessiyasi eskirgan, qaytadan kiring" });
  let u = users.find(x => x.tg_id === data.id);
  if (!u) {
    const name = [data.first_name, data.last_name].filter(Boolean).join(" ").trim() || (data.username ? "@" + data.username : "Telegram foydalanuvchi");
    u = { id: Date.now(), tg_id: data.id, tg_username: data.username || "", phone: "tg:" + data.id, name, created_at: Date.now() };
    users.push(u); persist();
  }
  res.json({ token: makeToken(u), user: { phone: u.phone, name: u.name } });
});

/* ============================ TELEFON (zaxira, kodsiz) ============================ */
app.post("/api/register/start", async (req, res) => {
  try {
    if (!rateOk("reg:" + clientIp(req), 10, 60000)) return res.status(429).json({ error: "Juda ko'p urinish, biroz kuting" });
    const phone = normPhone(req.body.phone);
    const name = (req.body.name || "").trim();
    const password = req.body.password || "";
    if (!phone) return res.status(400).json({ error: "Telefon raqam noto'g'ri" });
    if (password === "__resend__") return res.json({ ok: true });
    if (!name) return res.status(400).json({ error: "Ismni kiriting" });
    if (password.length < 4) return res.status(400).json({ error: "Parol juda qisqa" });
    if (users.some(u => u.phone === phone)) return res.status(409).json({ error: "Bu raqam allaqachon ro'yxatdan o'tgan" });
    const hash = await bcrypt.hash(password, 10);
    const u = { id: Date.now(), phone, name, pass_hash: hash, created_at: Date.now() };
    users.push(u); persist();
    res.json({ token: makeToken(u), user: { phone: u.phone, name: u.name } });
  } catch (e) { res.status(500).json({ error: "Server xatosi" }); }
});
app.post("/api/login", async (req, res) => {
  if (!rateOk("login:" + clientIp(req), 10, 60000)) return res.status(429).json({ error: "Juda ko'p urinish, biroz kuting" });
  const phone = normPhone(req.body.phone);
  const password = req.body.password || "";
  const u = users.find(x => x.phone === phone);
  if (!u || !u.pass_hash) return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
  const ok = await bcrypt.compare(password, u.pass_hash);
  if (!ok) return res.status(401).json({ error: "Raqam yoki parol noto'g'ri" });
  res.json({ token: makeToken(u), user: { phone: u.phone, name: u.name } });
});

/* ============================ CONFIG / STATS ============================ */
// Frontend bot username ni shu yerdan ishonchli oladi (tugma chiqishi uchun)
app.get("/api/config", (req, res) => res.json({ tg_bot: TG_BOT_USERNAME, paid_threshold: PAID_THRESHOLD }));
app.get("/api/stats", (req, res) => res.json({ users: users.length, threshold: PAID_THRESHOLD, paid_active: users.length >= PAID_THRESHOLD }));
app.get("/api/health", (req, res) => res.json({ ok: true, ai: AI_KEY ? "sozlangan" : "yo'q", telegram: (TG_BOT_TOKEN && TG_BOT_USERNAME) ? "ulangan" : "yo'q" }));

/* ============================ AI PROXY (kalit serverda qoladi) ============================ */
app.post("/api/chat", async (req, res) => {
  if (!rateOk("chat:" + clientIp(req), 40, 60000)) return res.status(429).json({ error: "Juda ko'p so'rov, biroz kuting" });
  if (!AI_KEY) return res.status(500).json({ error: "Server AI kaliti sozlanmagan (AI_API_KEY)" });
  const body = req.body || {};
  try {
    if (AI_PROVIDER === "anthropic") {
      const payload = Object.assign({ model: AI_MODEL, max_tokens: 1024 }, body);
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": AI_KEY, "anthropic-version": "2023-06-01" },
        body: JSON.stringify(payload)
      });
      return res.status(r.status).json(await r.json());
    }
    const msgs = [];
    if (body.system) msgs.push({ role: "system", content: String(body.system) });
    (body.messages || []).forEach(m => msgs.push({ role: (m.role === "assistant" ? "assistant" : "user"), content: textFromContent(m.content) }));
    const r = await fetch(AI_BASE + "/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + AI_KEY },
      body: JSON.stringify({ model: AI_MODEL, messages: msgs, max_tokens: body.max_tokens || 1024, temperature: 0.7 })
    });
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json({ error: (data.error && (data.error.message || data.error)) || "AI xatosi" });
    const text = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || "";
    return res.json({ content: [{ type: "text", text: text }] });
  } catch (e) { res.status(502).json({ error: "AI xizmatiga ulanib bo'lmadi" }); }
});

/* ============================ FRONTEND ============================ */
let HTML = "";
try {
  HTML = fs.readFileSync(path.join(__dirname, "Zako.html"), "utf8")
    .replace("const ZAKO_BACKEND=''", "const ZAKO_BACKEND='/api'")
    .replace("const ZAKO_TG_BOT=''", "const ZAKO_TG_BOT='" + TG_BOT_USERNAME + "'");
} catch (e) { console.error("Zako.html topilmadi! server.js bilan bir papkada bo'lsin."); }
app.get("/", (req, res) => res.type("html").send(HTML));

app.listen(PORT, () => {
  console.log("\n  \u2705 Zako server ishga tushdi:  http://localhost:" + PORT);
  console.log("  \u2022 AI:              " + (AI_KEY ? ("ulangan \u2713 (" + AI_MODEL + ")") : "YO'Q \u2014 AI_API_KEY qo'shing"));
  console.log("  \u2022 Telegram login:  " + (TG_BOT_TOKEN && TG_BOT_USERNAME ? ("ulangan \u2713 @" + TG_BOT_USERNAME) : "YO'Q \u2014 TG_BOT_TOKEN va TG_BOT_USERNAME qo'shing"));
  console.log("  \u2022 Ro'yxatdagilar:  " + users.length + "\n");
});
