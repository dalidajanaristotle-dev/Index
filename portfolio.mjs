import { getStore } from "@netlify/blobs";
import { pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";

// Starting password is stored only as a salted hash. Change it from the Security tab.
const DEFAULT_AUTH = { salt: "f479cd7bb128d12a2c161d5898b7f43b", iter: 150000, hash: "ef65b46bc786610b02215e43f740299beeb6be74cad38bc978e95ddc8afad0c6" };
const MAX_UPLOAD = 5.5 * 1024 * 1024;
const MAX_DATA = 900 * 1024;
const TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif", "video/mp4", "video/webm"]);

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function matches(pw, auth) {
  try {
    const got = pbkdf2Sync(pw, Buffer.from(auth.salt, "hex"), auth.iter, 32, "sha256");
    const want = Buffer.from(auth.hash, "hex");
    return got.length === want.length && timingSafeEqual(got, want);
  } catch {
    return false;
  }
}

function mediaResponse(file, rangeHeader) {
  const bytes = new Uint8Array(file.data);
  const type = (file.metadata && file.metadata.type) || "application/octet-stream";
  const base = {
    "content-type": type,
    "accept-ranges": "bytes",
    "cache-control": "public, max-age=31536000, immutable",
    "x-content-type-options": "nosniff",
  };
  const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader || "");
  if (m && (m[1] || m[2])) {
    let start = m[1] ? parseInt(m[1], 10) : Math.max(0, bytes.length - parseInt(m[2], 10));
    let end = m[1] && m[2] ? parseInt(m[2], 10) : bytes.length - 1;
    end = Math.min(end, bytes.length - 1);
    if (start > end || start >= bytes.length) {
      return new Response(null, { status: 416, headers: { ...base, "content-range": "bytes */" + bytes.length } });
    }
    return new Response(bytes.slice(start, end + 1), {
      status: 206,
      headers: { ...base, "content-range": "bytes " + start + "-" + end + "/" + bytes.length },
    });
  }
  return new Response(bytes, { status: 200, headers: base });
}

export default async (req) => {
  const url = new URL(req.url);
  const store = getStore("portfolio");
  const media = getStore("portfolio-media");

  if (req.method === "GET") {
    const id = url.searchParams.get("media");
    if (id) {
      if (!/^[a-f0-9]{32}$/.test(id)) return json({ error: "not found" }, 404);
      const file = await media.getWithMetadata(id, { type: "arrayBuffer" });
      if (!file) return json({ error: "not found" }, 404);
      return mediaResponse(file, req.headers.get("range"));
    }
    const data = await store.get("data", { type: "json" });
    return json({ data: data || null });
  }

  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  let password = "";
  try { password = decodeURIComponent(req.headers.get("x-dev-password") || ""); } catch { password = ""; }
  const auth = (await store.get("auth", { type: "json" })) || DEFAULT_AUTH;
  if (!password || !matches(password, auth)) {
    await sleep(800);
    return json({ error: "unauthorized" }, 401);
  }

  const action = url.searchParams.get("action");

  if (action === "verify") return json({ ok: true });

  if (action === "save") {
    let body;
    try { body = await req.json(); } catch { return json({ error: "bad request" }, 400); }
    const data = body && body.data;
    if (!data || typeof data !== "object" || Array.isArray(data)) return json({ error: "bad request" }, 400);
    delete data.auth;
    data.sample = false;
    const text = JSON.stringify(data);
    if (text.length > MAX_DATA) return json({ error: "too large" }, 413);
    await store.set("data", text);
    return json({ ok: true });
  }

  if (action === "upload") {
    const type = (req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    if (!TYPES.has(type)) return json({ error: "unsupported type" }, 415);
    const buf = await req.arrayBuffer();
    if (buf.byteLength === 0) return json({ error: "empty" }, 400);
    if (buf.byteLength > MAX_UPLOAD) return json({ error: "too large" }, 413);
    const id = randomBytes(16).toString("hex");
    await media.set(id, buf, { metadata: { type } });
    return json({ id });
  }

  if (action === "password") {
    let body;
    try { body = await req.json(); } catch { return json({ error: "bad request" }, 400); }
    const next = body && body.password;
    if (typeof next !== "string" || next.length < 8 || next.length > 200) return json({ error: "bad request" }, 400);
    const salt = randomBytes(16);
    const hash = pbkdf2Sync(next, salt, 150000, 32, "sha256");
    await store.set("auth", JSON.stringify({ salt: salt.toString("hex"), iter: 150000, hash: hash.toString("hex") }));
    return json({ ok: true });
  }

  return json({ error: "unknown action" }, 400);
};
