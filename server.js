require("dotenv").config({ quiet: true });

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");
const { MongoClient } = require("mongodb");
const nodemailer = require("nodemailer");
const { PutObjectCommand, S3Client } = require("@aws-sdk/client-s3");
const Sentry = require("@sentry/node");

const root = __dirname;
const dbFile = path.join(root, "data", "db.json");
const sampleDbFile = path.join(root, "data", "db.sample.json");
const backupDir = path.join(root, "backups");
const port = Number(process.env.PORT || 3000);
const sessionTtlMs = Number(process.env.SESSION_TTL_MINUTES || 120) * 60 * 1000;
const loginWindowMs = Number(process.env.LOGIN_WINDOW_MINUTES || 15) * 60 * 1000;
const maxLoginAttempts = Number(process.env.LOGIN_MAX_ATTEMPTS || 8);
const isProduction = process.env.NODE_ENV === "production";
const publicBaseUrl = String(process.env.PUBLIC_BASE_URL || `http://localhost:${port}`).replace(/\/$/, "");
const collections = new Set(["tenants", "rooms", "payments", "complaints", "notices", "services", "staff", "inventory", "expenses", "paymentSettings"]);
const rolePermissions = {
  owner: ["*"],
  admin: ["*"],
  manager: ["tenants:read", "tenants:write", "rooms:read", "rooms:write", "complaints:read", "complaints:write", "notices:read", "notices:write", "services:read", "services:write", "staff:read", "staff:write", "inventory:read", "inventory:write", "payments:read", "backup:read", "audit:read", "outbox:read"],
  accountant: ["payments:read", "payments:write", "payments:verify", "expenses:read", "expenses:write", "paymentSettings:read", "paymentSettings:write", "backup:read", "audit:read", "outbox:read", "outbox:write"],
  caretaker: ["rooms:read", "complaints:read", "complaints:write", "services:read", "services:write", "inventory:read", "notices:read"],
  tenant: ["self:read", "complaints:write", "services:write", "payments:submit", "payments:read", "notices:read"]
};
let mongoClient = null;
let mongoDb = null;
let mongoStore = null;
let mailTransporter = null;
let etherealAccount = null;
let s3Client = null;
const arrayCollections = ["tenants", "rooms", "payments", "complaints", "notices", "services", "staff", "inventory", "expenses", "auditLogs", "errorLogs", "outbox", "sessions", "users"];
const singletonCollections = ["paymentSettings", "security"];

function loadSeedDb() {
  const source = fs.existsSync(dbFile) ? dbFile : sampleDbFile;
  return JSON.parse(fs.readFileSync(source, "utf8"));
}

if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || "development",
    tracesSampleRate: Number(process.env.SENTRY_TRACES_SAMPLE_RATE || 0)
  });
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(String(password), salt, 210000, 32, "sha512").toString("hex");
  return { salt, passwordHash: hash };
}

function verifyPassword(password, user) {
  if (!user?.salt || !user?.passwordHash) return false;
  const candidate = hashPassword(password, user.salt).passwordHash;
  return crypto.timingSafeEqual(Buffer.from(candidate, "hex"), Buffer.from(user.passwordHash, "hex"));
}

function timingSafeTextEqual(a = "", b = "") {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function parseDataImage(value = "") {
  const match = String(value).match(/^data:image\/(png|jpeg|jpg|webp|gif);base64,(.+)$/i);
  if (!match) return null;
  return {
    ext: match[1].toLowerCase().replace("jpeg", "jpg"),
    contentType: `image/${match[1].toLowerCase().replace("jpg", "jpeg")}`,
    buffer: Buffer.from(match[2], "base64")
  };
}

async function storeImageIfConfigured(value, folder = "uploads") {
  const image = parseDataImage(value);
  if (!image) return value;
  if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_UPLOAD_PRESET) {
    const form = new FormData();
    form.set("file", value);
    form.set("upload_preset", process.env.CLOUDINARY_UPLOAD_PRESET);
    form.set("folder", folder);
    const response = await fetch(`https://api.cloudinary.com/v1_1/${encodeURIComponent(process.env.CLOUDINARY_CLOUD_NAME)}/image/upload`, {
      method: "POST",
      body: form
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error?.message || `Cloudinary returned ${response.status}`);
    return data.secure_url || data.url || value;
  }
  if (process.env.S3_BUCKET && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    s3Client ||= new S3Client({
      region: process.env.AWS_REGION || "ap-south-1",
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    });
    const key = `${folder}/${Date.now()}-${crypto.randomBytes(6).toString("hex")}.${image.ext}`;
    await s3Client.send(new PutObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: key,
      Body: image.buffer,
      ContentType: image.contentType,
      ACL: process.env.S3_PUBLIC_READ === "true" ? "public-read" : undefined
    }));
    if (process.env.S3_PUBLIC_BASE_URL) return `${process.env.S3_PUBLIC_BASE_URL.replace(/\/$/, "")}/${key}`;
    return `https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION || "ap-south-1"}.amazonaws.com/${key}`;
  }
  return value;
}

async function initStorage() {
  if (!process.env.MONGODB_URI) return;
  mongoClient = new MongoClient(process.env.MONGODB_URI);
  await mongoClient.connect();
  const databaseName = process.env.MONGODB_DB || new URL(process.env.MONGODB_URI).pathname.replace("/", "") || "staywise_pg";
  mongoDb = mongoClient.db(databaseName);
  if (process.env.DB_MODE === "collections") {
    const meta = await mongoDb.collection("_meta").findOne({ _id: "main" });
    if (!meta) {
      const seed = loadSeedDb();
      await writeCollections(seed);
      await mongoDb.collection("_meta").replaceOne({ _id: "main" }, { _id: "main", initializedAt: new Date(), mode: "collections" }, { upsert: true });
    }
    return;
  }
  mongoStore = mongoDb.collection("app_state");
  const existing = await mongoStore.findOne({ _id: "main" });
  if (!existing) {
    await mongoStore.insertOne({ _id: "main", ...loadSeedDb() });
  }
}

async function readDb() {
  if (mongoDb && process.env.DB_MODE === "collections") return readCollections();
  if (mongoStore) {
    const document = await mongoStore.findOne({ _id: "main" });
    if (!document) return loadSeedDb();
    const { _id, ...db } = document;
    return db;
  }
  return loadSeedDb();
}

async function writeDb(db) {
  if (mongoDb && process.env.DB_MODE === "collections") {
    await writeCollections(db);
    return;
  }
  if (mongoStore) {
    await mongoStore.replaceOne({ _id: "main" }, { _id: "main", ...db }, { upsert: true });
    return;
  }
  fs.mkdirSync(path.dirname(dbFile), { recursive: true });
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
}

async function readCollections() {
  const db = {};
  for (const name of arrayCollections) {
    db[name] = await mongoDb.collection(name).find({}).toArray();
    db[name] = db[name].map(({ _id, ...item }) => item);
  }
  for (const name of singletonCollections) {
    const doc = await mongoDb.collection(name).findOne({ _id: "main" });
    const { _id, ...value } = doc || {};
    db[name] = value || (name === "security" ? { loginAttempts: {} } : {});
  }
  return { ...loadSeedDb(), ...db };
}

async function writeCollections(db) {
  for (const name of arrayCollections) {
    const collection = mongoDb.collection(name);
    await collection.deleteMany({});
    const rows = (db[name] || []).map((item, index) => ({ _id: item.id || item.num || item.tokenHash || `${name}-${index}`, ...item }));
    if (rows.length) await collection.insertMany(rows);
  }
  for (const name of singletonCollections) {
    await mongoDb.collection(name).replaceOne({ _id: "main" }, { _id: "main", ...(db[name] || {}) }, { upsert: true });
  }
}

function seedUser(id, role, name, email, password, meta) {
  return { id, role, name, email: String(email).toLowerCase(), ...hashPassword(password), meta, active: true, createdAt: nowStamp() };
}

function normalizeRole(role) {
  return role === "admin" ? "admin" : String(role || "tenant");
}

function permissionsFor(user) {
  return rolePermissions[normalizeRole(user?.role)] || [];
}

function can(user, permission) {
  const permissions = permissionsFor(user);
  return permissions.includes("*") || permissions.includes(permission);
}

async function ensureDb() {
  const db = await readDb();
  db.auditLogs ||= [];
  db.errorLogs ||= [];
  db.outbox ||= [];
  db.sessions ||= [];
  db.security ||= { loginAttempts: {} };
  db.users ||= [];
  if (!db.users.length) {
    const generatedAdminPassword = crypto.randomBytes(12).toString("base64url");
    const generatedTenantPassword = crypto.randomBytes(12).toString("base64url");
    const adminPassword = process.env.ADMIN_PASSWORD || (isProduction ? "" : generatedAdminPassword);
    const tenantPassword = process.env.TENANT_PASSWORD || (isProduction ? "" : generatedTenantPassword);
    if (!adminPassword || !tenantPassword) {
      throw new Error("Set ADMIN_PASSWORD and TENANT_PASSWORD environment variables before production deployment.");
    }
    if (!isProduction && (!process.env.ADMIN_PASSWORD || !process.env.TENANT_PASSWORD)) {
      console.log(`Generated local admin password: ${adminPassword}`);
      console.log(`Generated local tenant password: ${tenantPassword}`);
    }
    db.users.push(seedUser("U001", "admin", "Admin Manager", process.env.ADMIN_EMAIL || "admin@staywise.in", adminPassword, "Property Manager"));
    const tenant = db.tenants?.[0];
    if (tenant?.email) db.users.push(seedUser("U002", "tenant", tenant.name, tenant.email, tenantPassword, `Room ${tenant.room}`));
    await writeDb(db);
  }
}

function audit(db, actor, action, details = {}) {
  db.auditLogs ||= [];
  db.auditLogs.unshift({
    id: "A" + String(db.auditLogs.length + 1).padStart(5, "0"),
    actor: actor?.email || "system",
    role: actor?.role || "system",
    action,
    details,
    at: nowStamp()
  });
  db.auditLogs = db.auditLogs.slice(0, 1000);
}

function enqueueMessage(db, type, to, subject, body, meta = {}) {
  db.outbox ||= [];
  db.outbox.unshift({
    id: "M" + String(db.outbox.length + 1).padStart(5, "0"),
    type,
    to,
    subject,
    body,
    meta,
    status: "queued",
    createdAt: nowStamp()
  });
  db.outbox = db.outbox.slice(0, 1000);
}

function notificationChannels() {
  return String(process.env.NOTIFY_CHANNELS || "email")
    .split(",")
    .map(item => item.trim().toLowerCase())
    .filter(Boolean);
}

function enqueueNotifications(db, recipient, subject, body, meta = {}) {
  const channels = notificationChannels();
  if (channels.includes("email") && recipient.email) enqueueMessage(db, "email", recipient.email, subject, body, meta);
  if (channels.includes("sms") && recipient.phone) enqueueMessage(db, "sms", recipient.phone, subject, body, meta);
  if (channels.includes("whatsapp") && recipient.phone) enqueueMessage(db, "whatsapp", recipient.phone, subject, body, meta);
}

function renderEmailTemplate(message) {
  const brand = process.env.EMAIL_BRAND_NAME || "StayWise PG";
  const accent = process.env.EMAIL_BRAND_COLOR || "#0f766e";
  const safeBody = String(message.body || "").replace(/[<>&]/g, char => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[char]));
  return `<!doctype html>
<html>
  <body style="margin:0;background:#f4f7fb;font-family:Arial,sans-serif;color:#111827">
    <div style="max-width:640px;margin:0 auto;padding:24px">
      <div style="background:${accent};color:white;padding:18px 22px;border-radius:8px 8px 0 0">
        <h1 style="font-size:20px;margin:0">${brand}</h1>
      </div>
      <div style="background:white;border:1px solid #e5e7eb;border-top:0;padding:22px;border-radius:0 0 8px 8px">
        <h2 style="font-size:18px;margin:0 0 14px">${message.subject}</h2>
        <p style="font-size:15px;line-height:1.6;white-space:pre-line;margin:0">${safeBody}</p>
        <p style="font-size:12px;color:#667085;margin:22px 0 0">This message was sent by ${brand}. Please contact your property admin for any correction.</p>
      </div>
    </div>
  </body>
</html>`;
}

function hasSmtpConfig() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function hasTwilioConfig() {
  return Boolean(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && (process.env.TWILIO_MESSAGING_SERVICE_SID || process.env.TWILIO_FROM_SMS || process.env.TWILIO_FROM_WHATSAPP));
}

async function getMailTransporter() {
  if (!hasSmtpConfig()) {
    if (process.env.ALLOW_ETHEREAL_TEST_EMAIL !== "true") return null;
    etherealAccount ||= await nodemailer.createTestAccount();
    if (!mailTransporter) {
      mailTransporter = nodemailer.createTransport({
        host: etherealAccount.smtp.host,
        port: etherealAccount.smtp.port,
        secure: etherealAccount.smtp.secure,
        auth: { user: etherealAccount.user, pass: etherealAccount.pass }
      });
    }
    return mailTransporter;
  }
  if (!mailTransporter) {
    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || "false") === "true",
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
  }
  return mailTransporter;
}

async function sendSmsMessage(message) {
  if (hasTwilioConfig()) return sendTwilioMessage(message);
  if (!process.env.SMS_WEBHOOK_URL) throw new Error("SMS_WEBHOOK_URL is not configured");
  const response = await fetch(process.env.SMS_WEBHOOK_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(process.env.SMS_WEBHOOK_TOKEN ? { Authorization: `Bearer ${process.env.SMS_WEBHOOK_TOKEN}` } : {})
    },
    body: JSON.stringify({ to: message.to, subject: message.subject, body: message.body, meta: message.meta || {} })
  });
  if (!response.ok) throw new Error(`SMS provider returned ${response.status}`);
}

async function sendTwilioMessage(message) {
  const isWhatsapp = message.type === "whatsapp";
  const to = isWhatsapp && !String(message.to).startsWith("whatsapp:") ? `whatsapp:${message.to}` : message.to;
  const from = isWhatsapp ? process.env.TWILIO_FROM_WHATSAPP : process.env.TWILIO_FROM_SMS;
  const params = new URLSearchParams({
    To: to,
    Body: message.body
  });
  if (process.env.TWILIO_MESSAGING_SERVICE_SID) {
    params.set("MessagingServiceSid", process.env.TWILIO_MESSAGING_SERVICE_SID);
  } else if (from) {
    params.set("From", from);
  } else {
    throw new Error(`Twilio ${message.type} sender is not configured`);
  }
  const auth = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString("base64");
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(process.env.TWILIO_ACCOUNT_SID)}/Messages.json`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: params
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || `Twilio returned ${response.status}`);
  message.provider = "twilio";
  message.providerMessageId = data.sid || "";
}

async function deliverOutbox(limit = 25) {
  const db = await readDb();
  db.outbox ||= [];
  const queued = db.outbox.filter(item => item.status === "queued").slice(0, limit);
  let sent = 0;
  for (const message of queued) {
    try {
      message.attempts = Number(message.attempts || 0) + 1;
      message.lastAttemptAt = nowStamp();
      if (message.type === "email") {
        const transporter = await getMailTransporter();
        if (!transporter) {
          message.status = "queued";
          message.lastError = "SMTP is not configured";
          continue;
        }
        const info = await transporter.sendMail({
          from: process.env.SMTP_FROM || process.env.SMTP_USER,
          to: message.to,
          subject: message.subject,
          text: message.body,
          html: renderEmailTemplate(message)
        });
        const previewUrl = nodemailer.getTestMessageUrl(info);
        if (previewUrl) message.previewUrl = previewUrl;
      } else if (message.type === "sms" || message.type === "whatsapp") {
        await sendSmsMessage(message);
      } else {
        throw new Error(`Unsupported message type: ${message.type}`);
      }
      message.status = "sent";
      message.sentAt = nowStamp();
      message.lastError = "";
      sent += 1;
    } catch (error) {
      message.status = message.attempts >= 5 ? "failed" : "queued";
      message.lastError = error.message;
    }
  }
  if (queued.length) await writeDb(db);
  return { processed: queued.length, sent };
}

async function reportError(error, context = {}) {
  const payload = {
    message: error?.message || String(error),
    stack: isProduction ? "" : error?.stack || "",
    context,
    at: new Date().toISOString(),
    service: "staywise-pg"
  };
  try {
    if (process.env.SENTRY_DSN) {
      Sentry.withScope(scope => {
        Object.entries(context || {}).forEach(([key, value]) => scope.setExtra(key, value));
        Sentry.captureException(error);
      });
    }
    if (process.env.ERROR_WEBHOOK_URL) {
      await fetch(process.env.ERROR_WEBHOOK_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(process.env.ERROR_WEBHOOK_TOKEN ? { Authorization: `Bearer ${process.env.ERROR_WEBHOOK_TOKEN}` } : {})
        },
        body: JSON.stringify(payload)
      });
    }
    if (process.env.LOGTAIL_SOURCE_TOKEN) {
      await fetch("https://in.logtail.com/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.LOGTAIL_SOURCE_TOKEN}`
        },
        body: JSON.stringify(payload)
      });
    }
  } catch {}
}

function send(res, status, body, headers = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": typeof body === "string" ? "text/html; charset=utf-8" : "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' https://unpkg.com 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; img-src 'self' data: https://api.qrserver.com https://images.unsplash.com; connect-src 'self'; frame-ancestors 'none';",
    ...headers
  });
  res.end(payload);
}

function notFound(res) {
  send(res, 404, { error: "Route not found" });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (raw.length > 5_000_000) reject(new Error("Payload too large"));
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object") {
          Object.defineProperty(parsed, "_rawBody", { value: raw, enumerable: false });
        }
        resolve(parsed);
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
  });
}

function sanitizeValue(value, key = "") {
  if (typeof value === "string") {
    const trimmed = value.trim().slice(0, key === "qrImage" ? 3_000_000 : 2000);
    if (key === "qrImage" && /^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(trimmed)) return trimmed;
    if (key === "qrImage" && /^https?:\/\//i.test(trimmed)) return trimmed;
    return trimmed.replace(/[<>]/g, "");
  }
  if (Array.isArray(value)) return value.map(item => sanitizeValue(item, key));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, sanitizeValue(v, k)]));
  }
  return value;
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ""));
}

function isAllowed(value, allowed) {
  return allowed.includes(String(value || ""));
}

function validateRecord(collection, row) {
  if (collection === "tenants") {
    if (!row.name) return "Tenant name is required";
    if (row.email && !validEmail(row.email)) return "Valid tenant email is required";
    if (row.phone && !/^\d{10}$/.test(String(row.phone))) return "Valid 10-digit phone is required";
    if (row.rent !== undefined && Number(row.rent) < 0) return "Rent must be positive";
  }
  if (collection === "rooms" && !row.num) return "Room number is required";
  if (collection === "payments") {
    if (!row.tenant || !row.room) return "Tenant and room are required";
    if (!Number.isFinite(Number(row.amount)) || Number(row.amount) < 0) return "Valid amount is required";
    if (!isAllowed(row.status, ["pending", "overdue", "verification_pending", "paid"])) return "Invalid payment status";
  }
  if (collection === "complaints" && !isAllowed(row.priority, ["High", "Medium", "Low"])) return "Invalid priority";
  if (collection === "services" && row.status && !isAllowed(row.status, ["pending", "completed"])) return "Invalid service status";
  return "";
}

function clientKey(req, email = "") {
  return `${req.socket.remoteAddress || "local"}:${String(email).toLowerCase()}`;
}

function checkLoginRate(req, email, db) {
  const key = clientKey(req, email);
  const now = Date.now();
  db.security ||= { loginAttempts: {} };
  db.security.loginAttempts ||= {};
  const entry = db.security.loginAttempts[key] || { count: 0, resetAt: now + loginWindowMs };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + loginWindowMs;
  }
  entry.count += 1;
  db.security.loginAttempts[key] = entry;
  return entry.count <= maxLoginAttempts;
}

function clearLoginRate(req, email, db) {
  if (db.security?.loginAttempts) delete db.security.loginAttempts[clientKey(req, email)];
}

function getCookieToken(req) {
  return (req.headers.cookie || "").split(";").map(part => part.trim()).find(part => part.startsWith("staywise_session="))?.split("=")[1] || "";
}

function sessionHash(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

async function createSession(db, user) {
  const token = crypto.randomBytes(32).toString("hex");
  db.sessions ||= [];
  const now = Date.now();
  db.sessions.unshift({
    tokenHash: sessionHash(token),
    userId: user.id,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + sessionTtlMs
  });
  db.sessions = db.sessions.filter(item => !item.revokedAt && item.expiresAt > now).slice(0, 2000);
  return token;
}

async function getSession(req) {
  const cookieToken = getCookieToken(req);
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "") || cookieToken;
  if (!token) return null;
  const db = await readDb();
  db.sessions ||= [];
  const tokenHash = sessionHash(token);
  const now = Date.now();
  const session = db.sessions.find(item => item.tokenHash === tokenHash && !item.revokedAt);
  if (!session || session.expiresAt <= now) return null;
  const user = (db.users || []).find(item => item.id === session.userId && item.active !== false);
  if (!user) return null;
  session.lastSeenAt = Date.now();
  await writeDb(db);
  return { ...session, user };
}

async function revokeSession(req) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "") || getCookieToken(req);
  if (!token) return;
  const db = await readDb();
  const tokenHash = sessionHash(token);
  const session = (db.sessions || []).find(item => item.tokenHash === tokenHash);
  if (session) {
    session.revokedAt = nowStamp();
    await writeDb(db);
  }
}

async function requireAuth(req, res) {
  const session = await getSession(req);
  if (!session) {
    send(res, 401, { error: "Login required" });
    return null;
  }
  return session;
}

async function requireAdmin(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return null;
  if (!can(session.user, "*")) {
    send(res, 403, { error: "Admin access required" });
    return null;
  }
  return session;
}

async function requirePermission(req, res, permission) {
  const session = await requireAuth(req, res);
  if (!session) return null;
  if (!can(session.user, permission)) {
    send(res, 403, { error: "Permission required: " + permission });
    return null;
  }
  return session;
}

function today() {
  return new Date().toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" });
}

function nowStamp() {
  return new Date().toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function publicUser(user) {
  return { id: user.id, role: user.role, name: user.name, email: user.email, meta: user.meta, permissions: permissionsFor(user), passwordResetRequired: Boolean(user.passwordResetRequired) };
}

function tenantScopedDb(db, user) {
  if (can(user, "*")) {
    const { users, errorLogs, sessions, security, outbox, ...safeDb } = db;
    delete safeDb.users;
    delete safeDb.errorLogs;
    delete safeDb.sessions;
    delete safeDb.security;
    delete safeDb.outbox;
    safeDb.auditLogs = (safeDb.auditLogs || []).slice(0, 100);
    return safeDb;
  }
  if (user.role !== "tenant") {
    const scoped = {
      tenants: can(user, "tenants:read") ? db.tenants : [],
      rooms: can(user, "rooms:read") ? db.rooms : [],
      payments: can(user, "payments:read") ? db.payments : [],
      paymentSettings: can(user, "paymentSettings:read") || can(user, "payments:read") ? db.paymentSettings : {},
      complaints: can(user, "complaints:read") ? db.complaints : [],
      notices: can(user, "notices:read") ? db.notices : [],
      services: can(user, "services:read") ? db.services : [],
      staff: can(user, "staff:read") ? db.staff : [],
      inventory: can(user, "inventory:read") ? db.inventory : [],
      expenses: can(user, "expenses:read") ? db.expenses : [],
      auditLogs: can(user, "audit:read") ? (db.auditLogs || []).slice(0, 100) : []
    };
    return scoped;
  }
  const tenant = db.tenants.find(item => item.email === user.email || item.name === user.name);
  if (!tenant) {
    return {
      tenants: [],
      rooms: [],
      payments: [],
      paymentSettings: db.paymentSettings,
      complaints: [],
      notices: db.notices,
      services: [],
      staff: [],
      inventory: [],
      expenses: []
    };
  }
  const name = tenant?.name || user.name;
  return {
    tenants: tenant ? [tenant] : [],
    rooms: tenant ? db.rooms.filter(room => room.num === tenant.room) : [],
    payments: db.payments.filter(item => item.tenant === name),
    paymentSettings: db.paymentSettings,
    complaints: db.complaints.filter(item => item.tenant === name),
    notices: db.notices,
    services: db.services.filter(item => item.tenant === name),
    staff: [],
    inventory: [],
    expenses: []
  };
}

function nextId(prefix, rows) {
  const next = rows.reduce((max, row) => {
    const value = Number(String(row.id || "").replace(/\D/g, ""));
    return Number.isFinite(value) ? Math.max(max, value) : max;
  }, 0) + 1;
  return prefix + String(next).padStart(3, "0");
}

function idKey(collection) {
  if (collection === "rooms") return "num";
  if (collection === "paymentSettings") return "id";
  return "id";
}

function prefixFor(collection) {
  return { tenants: "T", payments: "P", complaints: "C", notices: "N", services: "S", staff: "ST", inventory: "I", expenses: "E" }[collection] || "";
}

function recalculateInventoryStatus(row) {
  if (row && "stock" in row && "min" in row) row.status = Number(row.stock) < Number(row.min) ? "low" : "ok";
  return row;
}

function addTenantSideEffects(db, tenant) {
  const room = db.rooms.find(item => item.num === tenant.room);
  if (room) room.status = "occupied";
}

function removeTenantSideEffects(db, tenant) {
  if (!tenant) return;
  const room = db.rooms.find(item => item.num === tenant.room);
  if (room) room.status = "vacant";
}

function buildInvoice(payment, tenant, settings) {
  return {
    invoiceNo: payment.invoiceNo || `INV-${payment.id}`,
    paymentId: payment.id,
    status: payment.status,
    tenant: payment.tenant,
    phone: tenant?.phone || "",
    email: tenant?.email || "",
    room: payment.room,
    month: payment.month,
    amount: payment.amount,
    dueDate: payment.dueDate || "-",
    paidAt: payment.paidAt || payment.date || "-",
    method: payment.method || "-",
    transactionId: payment.transactionId || "-",
    verifiedBy: payment.verifiedBy || "-",
    verifiedAt: payment.verifiedAt || "-",
    businessName: settings?.businessName || "StayWise PG",
    upiId: settings?.upiId || "",
    generatedAt: nowStamp()
  };
}

function getWebhookPaymentId(body) {
  return body.paymentId || body.payment_id || body.notes?.paymentId || body.notes?.staywisePaymentId || body.payload?.payment?.entity?.notes?.paymentId || body.payload?.payment?.entity?.notes?.staywisePaymentId || body.payload?.payment_link?.entity?.reference_id || body.payload?.payment_link?.entity?.notes?.staywisePaymentId || "";
}

function getWebhookTransactionId(body) {
  return body.transactionId || body.utr || body.paymentGatewayId || body.razorpay_payment_id || body.payload?.payment?.entity?.id || "";
}

function getWebhookStatus(body) {
  return String(body.status || body.event || body.payload?.payment?.entity?.status || body.payload?.payment_link?.entity?.status || "").toLowerCase();
}

function paymentGatewayEnabled() {
  return Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);
}

async function createPaymentLink(payment, tenant) {
  if (!paymentGatewayEnabled()) {
    return {
      provider: "manual",
      paymentId: payment.id,
      amount: payment.amount,
      currency: "INR",
      checkoutUrl: "",
      message: "Razorpay keys are not configured. Use UPI QR/manual verification."
    };
  }
  const auth = Buffer.from(`${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`).toString("base64");
  const payload = {
    amount: Math.round(Number(payment.amount || 0) * 100),
    currency: "INR",
    accept_partial: false,
    reference_id: payment.id,
    description: `PG rent ${payment.month} - Room ${payment.room}`,
    customer: {
      name: tenant?.name || payment.tenant,
      email: tenant?.email || "",
      contact: tenant?.phone || ""
    },
    notify: {
      sms: Boolean(tenant?.phone),
      email: Boolean(tenant?.email)
    },
    reminder_enable: true,
    callback_url: `${publicBaseUrl}/`,
    callback_method: "get",
    notes: {
      staywisePaymentId: payment.id,
      tenant: payment.tenant,
      room: payment.room,
      month: payment.month
    }
  };
  const response = await fetch("https://api.razorpay.com/v1/payment_links", {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error?.description || `Razorpay returned ${response.status}`);
  return {
    provider: "razorpay",
    paymentId: payment.id,
    gatewayOrderId: data.id,
    checkoutUrl: data.short_url,
    amount: payment.amount,
    currency: "INR",
    status: data.status || "created"
  };
}

async function writeBackupSnapshot(reason = "scheduled") {
  const db = await readDb();
  fs.mkdirSync(backupDir, { recursive: true });
  const filename = `staywise-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  fs.writeFileSync(path.join(backupDir, filename), JSON.stringify({ reason, createdAt: nowStamp(), data: db }, null, 2));
  return filename;
}

function scheduleBackups() {
  const hours = Number(process.env.BACKUP_INTERVAL_HOURS || 0);
  if (!hours || hours < 1) return;
  setInterval(() => {
    writeBackupSnapshot("scheduled").catch(error => console.error("Backup failed:", error.message));
  }, hours * 60 * 60 * 1000);
}

function assertProductionReady() {
  if (!isProduction) return;
  const missing = [];
  if (!process.env.MONGODB_URI) missing.push("MONGODB_URI");
  if (!process.env.PAYMENT_WEBHOOK_SECRET) missing.push("PAYMENT_WEBHOOK_SECRET");
  if (!publicBaseUrl.startsWith("https://")) missing.push("PUBLIC_BASE_URL must start with https://");
  if (missing.length && process.env.ALLOW_INSECURE_PRODUCTION !== "true") {
    throw new Error(`Production readiness failed: ${missing.join(", ")}`);
  }
}

async function handleApi(req, res, url) {
  if (url.pathname === "/api/auth/login" && req.method === "POST") {
    const body = sanitizeValue(await parseBody(req));
    const db = await readDb();
    if (!checkLoginRate(req, body.email, db)) {
      await writeDb(db);
      return send(res, 429, { error: "Too many login attempts. Try again later." });
    }
    const loginRole = String(body.role || "admin");
    const user = (db.users || []).find(item => {
      const roleMatches = loginRole === "tenant" ? item.role === "tenant" : item.role !== "tenant";
      return item.email === String(body.email || "").toLowerCase() && roleMatches && item.active !== false;
    });
    if (!user || !verifyPassword(body.password || "", user)) {
      audit(db, { email: body.email, role: body.role }, "login_failed", { email: body.email, role: body.role });
      await writeDb(db);
      return send(res, 401, { error: "Invalid credentials" });
    }
    clearLoginRate(req, body.email, db);
    if (!user) return send(res, 401, { error: "Invalid credentials" });
    const token = await createSession(db, user);
    audit(db, user, "login_success");
    await writeDb(db);
    const secure = isProduction ? "; Secure" : "";
    return send(res, 200, { user: publicUser(user), data: tenantScopedDb(db, user) }, {
      "Set-Cookie": `staywise_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(sessionTtlMs / 1000)}${secure}`
    });
  }

  if (url.pathname === "/api/auth/logout" && req.method === "POST") {
    await revokeSession(req);
    return send(res, 200, { ok: true }, { "Set-Cookie": "staywise_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
  }

  if (url.pathname === "/api/auth/change-password" && req.method === "POST") {
    const session = await requireAuth(req, res);
    if (!session) return;
    const body = sanitizeValue(await parseBody(req));
    if (!body.currentPassword || !body.newPassword || String(body.newPassword).length < 10) {
      return send(res, 400, { error: "Current password and a 10+ character new password are required" });
    }
    const db = await readDb();
    const user = db.users.find(item => item.id === session.user.id);
    if (!user || !verifyPassword(body.currentPassword, user)) return send(res, 403, { error: "Current password is incorrect" });
    Object.assign(user, hashPassword(body.newPassword), { passwordChangedAt: nowStamp(), passwordResetRequired: false });
    audit(db, user, "password_changed");
    await writeDb(db);
    return send(res, 200, { ok: true });
  }

  if (url.pathname.match(/^\/api\/users\/[^/]+\/reset-password$/) && req.method === "POST") {
    const session = await requirePermission(req, res, "*");
    if (!session) return;
    const id = decodeURIComponent(url.pathname.split("/")[3]);
    const db = await readDb();
    const user = db.users.find(item => item.id === id);
    if (!user) return send(res, 404, { error: "User not found" });
    const temporaryPassword = crypto.randomBytes(10).toString("base64url");
    Object.assign(user, hashPassword(temporaryPassword), { passwordResetRequired: true, passwordChangedAt: nowStamp() });
    enqueueNotifications(db, { email: user.email }, "StayWise temporary password", `Your temporary password is ${temporaryPassword}. Please change it after login.`, { userId: id });
    audit(db, session.user, "password_reset", { userId: id });
    await writeDb(db);
    return send(res, 200, { user: publicUser(user), temporaryPassword });
  }

  if (url.pathname.match(/^\/api\/tenants\/[^/]+\/reset-password$/) && req.method === "POST") {
    const session = await requirePermission(req, res, "tenants:write");
    if (!session) return;
    const tenantId = decodeURIComponent(url.pathname.split("/")[3]);
    const db = await readDb();
    const tenant = db.tenants.find(item => item.id === tenantId);
    if (!tenant?.email) return send(res, 404, { error: "Tenant email not found" });
    const user = (db.users || []).find(item => item.email === String(tenant.email).toLowerCase());
    if (!user) return send(res, 404, { error: "Tenant login user not found" });
    const temporaryPassword = crypto.randomBytes(10).toString("base64url");
    Object.assign(user, hashPassword(temporaryPassword), { passwordResetRequired: true, passwordChangedAt: nowStamp() });
    enqueueNotifications(db, { email: user.email, phone: tenant.phone }, "StayWise temporary password", `Your temporary password is ${temporaryPassword}. Please change it after login.`, { tenantId });
    audit(db, session.user, "tenant_password_reset", { tenantId });
    await writeDb(db);
    return send(res, 200, { tenantId, temporaryPassword });
  }

  if (url.pathname === "/api/admin/audit-logs" && req.method === "GET") {
    const session = await requirePermission(req, res, "audit:read");
    if (!session) return;
    const db = await readDb();
    return send(res, 200, (db.auditLogs || []).slice(0, 500));
  }

  if (url.pathname === "/api/admin/outbox" && req.method === "GET") {
    const session = await requirePermission(req, res, "outbox:read");
    if (!session) return;
    const db = await readDb();
    return send(res, 200, (db.outbox || []).slice(0, 500).map(item => ({ ...item, body: item.type === "email" ? item.body : String(item.body || "").slice(0, 120) })));
  }

  if (url.pathname === "/api/admin/outbox/process" && req.method === "POST") {
    const session = await requirePermission(req, res, "outbox:write");
    if (!session) return;
    const result = await deliverOutbox();
    const db = await readDb();
    audit(db, session.user, "outbox_processed", result);
    await writeDb(db);
    return send(res, 200, result);
  }

  if (url.pathname === "/api/admin/readiness" && req.method === "GET") {
    const session = await requirePermission(req, res, "audit:read");
    if (!session) return;
    return send(res, 200, {
      nodeEnv: process.env.NODE_ENV || "development",
      httpsConfigured: publicBaseUrl.startsWith("https://"),
      mongoConfigured: Boolean(process.env.MONGODB_URI),
      dbMode: process.env.DB_MODE || "app_state",
      paymentWebhookConfigured: Boolean(process.env.PAYMENT_WEBHOOK_SECRET),
      razorpayConfigured: paymentGatewayEnabled(),
      smtpConfigured: hasSmtpConfig(),
      freeTestEmailEnabled: process.env.ALLOW_ETHEREAL_TEST_EMAIL === "true",
      twilioConfigured: hasTwilioConfig(),
      smsWebhookConfigured: Boolean(process.env.SMS_WEBHOOK_URL),
      monitoringConfigured: Boolean(process.env.SENTRY_DSN || process.env.ERROR_WEBHOOK_URL || process.env.LOGTAIL_SOURCE_TOKEN),
      sentryConfigured: Boolean(process.env.SENTRY_DSN),
      cloudinaryConfigured: Boolean(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_UPLOAD_PRESET),
      s3Configured: Boolean(process.env.S3_BUCKET && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY),
      backupIntervalHours: Number(process.env.BACKUP_INTERVAL_HOURS || 0)
    });
  }

  if (url.pathname === "/api/bootstrap" && req.method === "GET") {
    const session = await requireAuth(req, res);
    if (!session) return;
    return send(res, 200, { user: publicUser(session.user), data: tenantScopedDb(await readDb(), session.user) });
  }

  if (url.pathname === "/api/admin/backup" && req.method === "GET") {
    const session = await requirePermission(req, res, "backup:read");
    if (!session) return;
    const db = await readDb();
    audit(db, session.user, "backup_downloaded");
    await writeDb(db);
    writeBackupSnapshot("manual_download").catch(error => console.error("Backup snapshot failed:", error.message));
    return send(res, 200, db, { "Content-Disposition": `attachment; filename="staywise-backup-${Date.now()}.json"` });
  }

  if (url.pathname === "/api/payment-settings" && req.method === "PATCH") {
    const session = await requirePermission(req, res, "paymentSettings:write");
    if (!session) return;
    const db = await readDb();
    const body = sanitizeValue(await parseBody(req));
    if (body.qrImage && String(body.qrImage).length > 1_200_000) return send(res, 413, { error: "QR image is too large. Use a compressed image or hosted image URL." });
    if (body.qrImage) body.qrImage = await storeImageIfConfigured(body.qrImage, "payment-qr");
    db.paymentSettings = { ...(db.paymentSettings || {}), ...body };
    audit(db, session.user, "payment_settings_updated");
    await writeDb(db);
    return send(res, 200, db.paymentSettings);
  }

  if (url.pathname.match(/^\/api\/payments\/[^/]+\/submit$/) && req.method === "POST") {
    const session = await requireAuth(req, res);
    if (!session) return;
    const id = decodeURIComponent(url.pathname.split("/")[3]);
    const db = await readDb();
    const payment = db.payments.find(item => item.id === id);
    if (!payment) return send(res, 404, { error: "Payment not found" });
    const tenant = db.tenants.find(item => item.email === session.user.email || item.name === session.user.name);
    if (session.user.role !== "admin" && payment.tenant !== tenant?.name) return send(res, 403, { error: "You can submit only your own payment" });
    if (payment.status === "paid") return send(res, 409, { error: "Payment already verified as paid" });
    const body = sanitizeValue(await parseBody(req));
    if (!body.transactionId || !body.method) return send(res, 400, { error: "Payment method and transaction ID are required" });
    if (!isAllowed(body.method, ["PhonePe", "Google Pay", "Paytm", "BHIM UPI", "Bank Transfer", "Cash"])) return send(res, 400, { error: "Invalid payment method" });
    payment.status = "verification_pending";
    payment.method = body.method;
    payment.transactionId = body.transactionId;
    payment.paidAt = body.paidAt || nowStamp();
    payment.date = payment.paidAt;
    payment.payerNote = body.payerNote || "";
    payment.invoiceNo = payment.invoiceNo || `INV-${payment.id}`;
    payment.verificationNote = "Waiting for admin verification";
    audit(db, session.user, "payment_submitted", { paymentId: payment.id, method: payment.method });
    await writeDb(db);
    return send(res, 200, payment);
  }

  if (url.pathname.match(/^\/api\/payments\/[^/]+\/gateway-link$/) && req.method === "POST") {
    const session = await requireAuth(req, res);
    if (!session) return;
    const id = decodeURIComponent(url.pathname.split("/")[3]);
    const db = await readDb();
    const payment = db.payments.find(item => item.id === id);
    if (!payment) return send(res, 404, { error: "Payment not found" });
    const tenant = db.tenants.find(item => item.email === session.user.email || item.name === payment.tenant);
    if (session.user.role !== "admin" && payment.tenant !== tenant?.name) return send(res, 403, { error: "You can pay only your own dues" });
    if (payment.status === "paid") return send(res, 409, { error: "Payment already verified as paid" });
    if (payment.gatewayLink?.checkoutUrl) return send(res, 200, payment.gatewayLink);
    const link = await createPaymentLink(payment, tenant);
    payment.gatewayLink = { ...link, createdAt: nowStamp() };
    if (link.checkoutUrl) {
      enqueueNotifications(db, tenant || {}, "PG rent payment link", `Pay ${payment.month} rent using this secure link: ${link.checkoutUrl}`, { paymentId: payment.id, provider: link.provider });
    }
    audit(db, session.user, "payment_gateway_link_created", { paymentId: payment.id, provider: link.provider });
    await writeDb(db);
    return send(res, 200, payment.gatewayLink);
  }

  if (url.pathname.match(/^\/api\/payments\/[^/]+\/verify$/) && req.method === "PATCH") {
    const session = await requirePermission(req, res, "payments:verify");
    if (!session) return;
    const id = decodeURIComponent(url.pathname.split("/")[3]);
    const db = await readDb();
    const payment = db.payments.find(item => item.id === id);
    if (!payment) return send(res, 404, { error: "Payment not found" });
    payment.status = "paid";
    payment.verifiedBy = session.user.name;
    payment.verifiedAt = nowStamp();
    payment.invoiceNo = payment.invoiceNo || `INV-${payment.id}`;
    payment.verificationNote = "Verified by admin";
    audit(db, session.user, "payment_verified", { paymentId: payment.id });
    await writeDb(db);
    return send(res, 200, payment);
  }

  if (url.pathname.match(/^\/api\/payments\/[^/]+\/reject$/) && req.method === "PATCH") {
    const session = await requirePermission(req, res, "payments:verify");
    if (!session) return;
    const id = decodeURIComponent(url.pathname.split("/")[3]);
    const db = await readDb();
    const body = sanitizeValue(await parseBody(req));
    const payment = db.payments.find(item => item.id === id);
    if (!payment) return send(res, 404, { error: "Payment not found" });
    payment.status = "pending";
    payment.rejectedAt = nowStamp();
    payment.rejectedBy = session.user.name;
    payment.verificationNote = body.reason || "Payment proof rejected by admin";
    audit(db, session.user, "payment_rejected", { paymentId: payment.id, reason: payment.verificationNote });
    await writeDb(db);
    return send(res, 200, payment);
  }

  if (url.pathname.match(/^\/api\/payments\/[^/]+\/remind$/) && req.method === "POST") {
    const session = await requirePermission(req, res, "payments:write");
    if (!session) return;
    const id = decodeURIComponent(url.pathname.split("/")[3]);
    const db = await readDb();
    const payment = db.payments.find(item => item.id === id);
    if (!payment) return send(res, 404, { error: "Payment not found" });
    payment.reminderCount = Number(payment.reminderCount || 0) + 1;
    payment.lastReminderAt = nowStamp();
    payment.reminderNote = `Reminder sent for ${payment.month} dues`;
    const tenant = db.tenants.find(item => item.name === payment.tenant);
    if (tenant?.email || tenant?.phone) enqueueNotifications(db, tenant, "PG rent payment reminder", `${payment.month} rent of ${payment.amount} is pending. Due date: ${payment.dueDate || "-"}.`, { paymentId: payment.id });
    audit(db, session.user, "payment_reminder_sent", { paymentId: payment.id });
    await writeDb(db);
    return send(res, 200, payment);
  }

  if (url.pathname === "/api/payments/webhook" && req.method === "POST") {
    const body = await parseBody(req);
    const secret = process.env.PAYMENT_WEBHOOK_SECRET || "";
    if (!secret) return send(res, 503, { error: "Payment webhook secret is not configured" });
    const signature = req.headers["x-staywise-signature"] || req.headers["x-razorpay-signature"] || req.headers["x-webhook-signature"] || "";
    const expected = crypto.createHmac("sha256", secret).update(body._rawBody || "").digest("hex");
    if (!signature || !timingSafeTextEqual(signature, expected)) return send(res, 401, { error: "Invalid webhook signature" });
    const paymentId = getWebhookPaymentId(body);
    const transactionId = getWebhookTransactionId(body);
    const status = getWebhookStatus(body);
    if (!paymentId || !["paid", "captured", "success", "payment.captured"].includes(status)) return send(res, 202, { ok: true, ignored: true });
    const db = await readDb();
    const payment = db.payments.find(item => item.id === paymentId);
    if (!payment) return send(res, 404, { error: "Payment not found" });
    payment.status = "paid";
    payment.method = body.provider || body.method || "Payment Gateway";
    payment.transactionId = transactionId || payment.transactionId || "-";
    payment.paidAt = payment.paidAt || nowStamp();
    payment.date = payment.paidAt;
    payment.verifiedBy = "payment_webhook";
    payment.verifiedAt = nowStamp();
    payment.invoiceNo = payment.invoiceNo || `INV-${payment.id}`;
    payment.verificationNote = "Automatically verified by signed payment webhook";
    audit(db, { email: "payment_webhook", role: "system" }, "payment_webhook_verified", { paymentId: payment.id, transactionId: payment.transactionId });
    await writeDb(db);
    return send(res, 200, { ok: true, payment });
  }

  if (url.pathname.match(/^\/api\/payments\/[^/]+\/invoice$/) && req.method === "GET") {
    const session = await requireAuth(req, res);
    if (!session) return;
    const id = decodeURIComponent(url.pathname.split("/")[3]);
    const db = await readDb();
    const payment = db.payments.find(item => item.id === id);
    if (!payment) return send(res, 404, { error: "Payment not found" });
    const tenant = db.tenants.find(item => item.name === payment.tenant);
    if (session.user.role !== "admin" && tenant?.email !== session.user.email && payment.tenant !== session.user.name) {
      return send(res, 403, { error: "You can download only your own invoice" });
    }
    return send(res, 200, buildInvoice(payment, tenant, db.paymentSettings));
  }

  const parts = url.pathname.split("/").filter(Boolean);
  const collection = parts[1];
  const id = decodeURIComponent(parts[2] || "");
  if (parts[0] !== "api" || !collections.has(collection)) return notFound(res);

  if (req.method === "GET") {
    const session = await requireAuth(req, res);
    if (!session) return;
    const db = await readDb();
    const scopedDb = tenantScopedDb(db, session.user);
    if (collection === "paymentSettings") return send(res, 200, scopedDb.paymentSettings || {});
    return send(res, 200, scopedDb[collection] || []);
  }

  if (req.method === "POST" && ["complaints", "services"].includes(collection)) {
    const session = await requireAuth(req, res);
    if (!session) return;
    const db = await readDb();
    const rows = db[collection];
    const body = sanitizeValue(await parseBody(req));
    const tenant = db.tenants.find(item => item.email === session.user.email || item.name === session.user.name);
    const row = {
      ...body,
      id: nextId(prefixFor(collection), rows),
      tenant: session.user.role === "admin" ? body.tenant : tenant?.name || session.user.name,
      date: body.date || today()
    };
    if (collection === "complaints") row.status ||= "open";
    if (collection === "services") row.status ||= "pending";
    const error = validateRecord(collection, row);
    if (error) return send(res, 400, { error });
    rows.push(row);
    audit(db, session.user, `${collection}_created`, { id: row.id });
    await writeDb(db);
    return send(res, 201, row);
  }

  const session = await requirePermission(req, res, `${collection}:write`);
  if (!session) return;
  const db = await readDb();
  if (collection === "paymentSettings") return send(res, 405, { error: "Use /api/payment-settings to update payment settings" });
  const rows = db[collection];
  const key = idKey(collection);

  if (req.method === "POST") {
    const body = sanitizeValue(await parseBody(req));
    const row = { ...body };
    let temporaryPassword = "";
    if (row.email) row.email = String(row.email).toLowerCase();
    if (collection === "tenants" && row.email && !validEmail(row.email)) return send(res, 400, { error: "Valid tenant email is required" });
    if (collection !== "rooms" && !row.id) row.id = nextId(prefixFor(collection), rows);
    if (collection === "rooms" && !row.num) return send(res, 400, { error: "Room number is required" });
    if (collection === "payments" && row.status === "paid" && !row.date) row.date = today();
    if (collection === "payments") {
      row.dueDate ||= "07 " + row.month;
      row.invoiceNo ||= `INV-${row.id}`;
    }
    if (collection === "complaints") row.status ||= "open";
    if (collection === "services") row.status ||= "pending";
    recalculateInventoryStatus(row);
    const error = validateRecord(collection, row);
    if (error) return send(res, 400, { error });
    rows.push(row);
    if (collection === "tenants") {
      addTenantSideEffects(db, row);
      if (row.email && !(db.users || []).some(user => user.email === row.email)) {
        const tempPassword = crypto.randomBytes(8).toString("hex");
        db.users ||= [];
        db.users.push(seedUser("U" + String(db.users.length + 1).padStart(3, "0"), "tenant", row.name, row.email, tempPassword, `Room ${row.room}`));
        enqueueNotifications(db, row, "StayWise tenant portal access", `Your tenant portal temporary password is ${tempPassword}. Please change it after login.`, { tenantId: row.id });
        temporaryPassword = tempPassword;
      }
    }
    audit(db, session.user, `${collection}_created`, { id: row.id || row.num });
    await writeDb(db);
    return send(res, 201, temporaryPassword ? { ...row, temporaryPassword } : row);
  }

  const index = rows.findIndex(item => String(item[key]) === id);
  if (index === -1) return send(res, 404, { error: "Record not found" });

  if (req.method === "PATCH") {
    const body = sanitizeValue(await parseBody(req));
    const row = recalculateInventoryStatus({ ...rows[index], ...body });
    if (collection === "payments" && row.status === "paid" && row.date === "-") row.date = today();
    const error = validateRecord(collection, row);
    if (error) return send(res, 400, { error });
    rows[index] = row;
    audit(db, session.user, `${collection}_updated`, { id });
    await writeDb(db);
    return send(res, 200, row);
  }

  if (req.method === "DELETE") {
    const [removed] = rows.splice(index, 1);
    if (collection === "tenants") removeTenantSideEffects(db, removed);
    audit(db, session.user, `${collection}_deleted`, { id });
    await writeDb(db);
    return send(res, 200, removed);
  }

  return notFound(res);
}

function serveStatic(req, res, url) {
  const file = url.pathname === "/" ? "pg_hostel_final.html" : decodeURIComponent(url.pathname.slice(1));
  const allowedPublicFiles = new Set(["pg_hostel_final.html"]);
  if (!allowedPublicFiles.has(file)) return notFound(res);
  const requested = path.normalize(path.join(root, file));
  if (!requested.startsWith(root)) return send(res, 403, "Forbidden");
  if (!fs.existsSync(requested) || fs.statSync(requested).isDirectory()) return notFound(res);
  const ext = path.extname(requested).toLowerCase();
  const types = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8" };
  res.writeHead(200, {
    "Content-Type": types[ext] || "application/octet-stream",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' https://unpkg.com 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; img-src 'self' data: https://api.qrserver.com https://images.unsplash.com; connect-src 'self'; frame-ancestors 'none';"
  });
  fs.createReadStream(requested).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (isProduction && req.headers["x-forwarded-proto"] && req.headers["x-forwarded-proto"] !== "https") {
      res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
      return res.end();
    }
    if (url.pathname.startsWith("/api/")) return await handleApi(req, res, url);
    return serveStatic(req, res, url);
  } catch (error) {
    try {
      const db = await readDb();
      db.errorLogs ||= [];
      db.errorLogs.unshift({ at: nowStamp(), path: url.pathname, message: error.message, stack: isProduction ? "" : error.stack });
      db.errorLogs = db.errorLogs.slice(0, 500);
      await writeDb(db);
    } catch {}
    reportError(error, { path: url.pathname, method: req.method }).catch(() => {});
    send(res, 500, { error: isProduction ? "Server error" : (error.message || "Server error") });
  }
});

(async () => {
  assertProductionReady();
  await initStorage();
  await ensureDb();
  scheduleBackups();
  server.listen(port, () => {
    console.log(`StayWise running at http://localhost:${port}`);
    console.log(process.env.MONGODB_URI ? "Storage: MongoDB" : "Storage: local JSON");
  });
})().catch(error => {
  reportError(error, { phase: "startup" }).catch(() => {});
  console.error("Startup failed:", error);
  process.exit(1);
});
