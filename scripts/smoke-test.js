const assert = require("node:assert");
const http = require("node:http");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
require("dotenv").config({ quiet: true });

const port = Number(process.env.SMOKE_PORT || 3102);
const base = `http://localhost:${port}`;
let server;

function request(method, urlPath, { body, cookie } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : "";
    const req = http.request(`${base}${urlPath}`, {
      method,
      headers: {
        ...(payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {}),
        ...(cookie ? { Cookie: cookie } : {})
      }
    }, res => {
      let raw = "";
      res.on("data", chunk => raw += chunk);
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          cookie: res.headers["set-cookie"]?.[0]?.split(";")[0] || "",
          body: raw && (res.headers["content-type"] || "").includes("application/json") ? JSON.parse(raw) : raw
        });
      });
    });
    req.on("error", reject);
    req.end(payload);
  });
}

function waitForServer() {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = async () => {
      try {
        const res = await request("GET", "/");
        if (res.status === 200) return resolve();
      } catch {}
      if (Date.now() - started > 45000) return reject(new Error("Server did not start"));
      setTimeout(tick, 500);
    };
    tick();
  });
}

(async () => {
  const out = fs.openSync(path.join(process.env.TEMP || ".", "staywise-smoke.out.log"), "w");
  const err = fs.openSync(path.join(process.env.TEMP || ".", "staywise-smoke.err.log"), "w");
  server = spawn(process.execPath, ["server.js"], { stdio: ["ignore", out, err], env: { ...process.env, PORT: String(port) } });
  await waitForServer();

  const leak = await request("GET", "/data/db.json");
  assert.equal(leak.status, 404);

  const login = await request("POST", "/api/auth/login", {
    body: { email: process.env.SMOKE_ADMIN_EMAIL || "admin@staywise.in", password: process.env.SMOKE_ADMIN_PASSWORD, role: "admin" }
  });
  assert.equal(login.status, 200, "Admin login failed. Set SMOKE_ADMIN_PASSWORD.");
  assert.equal(Object.prototype.hasOwnProperty.call(login.body.data, "users"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(login.body.data, "sessions"), false);

  const readiness = await request("GET", "/api/admin/readiness", { cookie: login.cookie });
  assert.equal(readiness.status, 200);

  console.log(JSON.stringify({ ok: true, leakStatus: leak.status, readiness: readiness.body }));
})().finally(() => {
  if (server) server.kill();
});
