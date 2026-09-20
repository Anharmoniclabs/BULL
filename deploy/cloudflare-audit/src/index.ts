export interface Env {
  DB: D1Database;
  BULL_ANCHOR_MASTER_KEY: string;
}

const MAX_FRAME = 65536;
const HEX64 = /^[a-f0-9]{64}$/;

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const obj = value as Record<string, unknown>;
  return "{" + Object.keys(obj).sort().map(k => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
}

async function hmac(keyBytes: Uint8Array, data: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, data));
}

async function deriveSessionKey(master: string, session: string): Promise<Uint8Array> {
  if (!HEX64.test(session)) throw new Error("invalid session");
  const masterBytes = new TextEncoder().encode(master);
  if (masterBytes.byteLength < 32) throw new Error("master key too short");
  const mac = await hmac(masterBytes, new TextEncoder().encode("bull-anchor-session-v1:" + session));
  return Uint8Array.from(mac.match(/../g)!.map(x => parseInt(x, 16)));
}

async function authenticate(body: Record<string, unknown>, key: Uint8Array, purpose: string) {
  const clean = { ...body };
  delete clean.mac;
  const mac = await hmac(key, new TextEncoder().encode(purpose + "\0" + canonical(clean)));
  return { ...clean, mac };
}

async function verifyMac(message: Record<string, unknown>, key: Uint8Array, purpose: string) {
  const supplied = message.mac;
  if (typeof supplied !== "string") throw new Error("missing mac");
  const expected = await authenticate(message, key, purpose);
  if (expected.mac !== supplied) throw new Error("authentication failed");
}

function reject(): Response {
  return Response.json({ error: "checkpoint rejected" }, { status: 409, headers: { "cache-control": "no-store" } });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/v1/checkpoints") {
      return new Response("Not Found", { status: 404 });
    }
    const length = Number(request.headers.get("content-length") || "0");
    if (!Number.isInteger(length) || length < 1 || length > MAX_FRAME) return reject();

    try {
      const raw = await request.text();
      if (new TextEncoder().encode(raw).byteLength > MAX_FRAME) throw new Error("frame too large");
      const message = JSON.parse(raw) as Record<string, unknown>;
      const allowed = new Set(["version", "session", "sequence", "head_hash", "previous_hash", "mac"]);
      if (Object.keys(message).some(k => !allowed.has(k))) throw new Error("unexpected field");

      const session = message.session;
      const sequence = message.sequence;
      const head = message.head_hash;
      const previous = message.previous_hash ?? null;

      if (message.version !== 1 || typeof session !== "string" || !HEX64.test(session) ||
          !Number.isInteger(sequence) || (sequence as number) < 1 || (sequence as number) > 1_000_000 ||
          typeof head !== "string" || !HEX64.test(head) ||
          !(previous === null || (typeof previous === "string" && HEX64.test(previous)))) {
        throw new Error("invalid checkpoint");
      }

      const key = await deriveSessionKey(env.BULL_ANCHOR_MASTER_KEY, session);
      await verifyMac(message, key, "checkpoint");
      const seq = sequence as number;
      const frame = canonical(message);

      // Atomic acceptance condition: only the next sequence whose previous hash
      // matches the latest committed head can insert. Exact latest retries are
      // accepted below after reading the row.
      await env.DB.prepare(`
        INSERT INTO checkpoints(session, sequence, head, previous_hash, frame)
        SELECT ?1, ?2, ?3, ?4, ?5
        WHERE ?2 = COALESCE(
          (SELECT sequence + 1 FROM checkpoints WHERE session = ?1 ORDER BY sequence DESC LIMIT 1), 1
        )
        AND COALESCE(?4, '') = COALESCE(
          (SELECT head FROM checkpoints WHERE session = ?1 ORDER BY sequence DESC LIMIT 1), ''
        )
        ON CONFLICT(session, sequence) DO NOTHING
      `).bind(session, seq, head, previous, frame).run();

      const row = await env.DB.prepare(
        "SELECT head, frame FROM checkpoints WHERE session = ? AND sequence = ?"
      ).bind(session, seq).first<{head: string; frame: string}>();

      if (!row || row.head !== head || row.frame !== frame) throw new Error("replay, conflict, or sequence gap");

      const ack = await authenticate({
        version: 1,
        session,
        sequence: seq,
        head_hash: head,
        accepted: true,
      }, key, "acknowledgement");

      return Response.json(ack, { status: 200, headers: { "cache-control": "no-store" } });
    } catch {
      return reject();
    }
  }
};