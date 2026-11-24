// A Convo node on Cloudflare (spec Part IV): one Durable Object per node
// key, running the node's Swift core as a WebAssembly reactor
// (convo_node_worker.wasm). A Durable Object is a single instance per ID, so
// the node's log has one writer; its SQLite storage keeps the node's files
// (wasi.js); its alarm closes batches and gathers witnesses' cosignatures
// (spec §7, §11). The Worker itself only routes every request to the node's
// object, which gives a client the node let through on `/ice` a Cloudflare
// TURN credential of its own (§21).
import { DurableObject } from "cloudflare:workers";
import wasm from "./convo_node_worker.wasm";
import { SqliteFiles, wasiImports } from "./wasi.js";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Convo-Auth",
};
const STUN = "stun:stun.cloudflare.com:3478";
// A client's own TURN credential lasts an hour; it asks again after.
const TURN_TTL = 3600;
// No request body over this is read: the node's largest (a blob,
// Reactor.swift's maxBlobBytes) and its encoding's room.
const MAX_BODY = 2 * 1024 * 1024;
const decoder = new TextDecoder();
const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const id = env.CONVO_NODE.idFromName(env.NODE_NAME || "node");
    return env.CONVO_NODE.get(id).fetch(request);
  },
};

export class ConvoNode extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.reactor = null;
  }

  /** The reactor, started on first use with the node's configuration. */
  start(origin) {
    if (this.reactor) return this.reactor;
    const sql = this.ctx.storage.sql;
    sql.exec("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)");
    const saved = sql.exec("SELECT value FROM meta WHERE key = 'origin'").toArray()[0];
    const publicURL = this.env.PUBLIC_URL || (saved && saved.value) || origin;
    if (origin && !saved) sql.exec("INSERT OR REPLACE INTO meta (key, value) VALUES ('origin', ?)", origin);
    const files = new SqliteFiles(sql);
    let instance;
    instance = new WebAssembly.Instance(wasm, {
      wasi_snapshot_preview1: wasiImports(files, () => instance.exports.memory, (line) => console.log(line)),
    });
    instance.exports._initialize();
    const list = (value) => (value || "").split(",").map((s) => s.trim()).filter(Boolean);
    const reactor = {
      exports: instance.exports,
      call(name, value) {
        const input = encoder.encode(typeof value === "string" ? value : JSON.stringify(value));
        const exports = instance.exports;
        const ptr = exports.convo_alloc(input.length);
        new Uint8Array(exports.memory.buffer).set(input, ptr);
        const length = exports[name](ptr, input.length);
        exports.convo_free(ptr);
        return reactor.result(length);
      },
      result(length) {
        const exports = instance.exports;
        const at = exports.convo_result_ptr();
        return JSON.parse(decoder.decode(new Uint8Array(exports.memory.buffer, at, length)));
      },
      logs() {
        for (const line of reactor.result(instance.exports.convo_node_logs())) console.log(line);
      },
    };
    const started = reactor.call("convo_node_init", {
      id: this.env.NODE_ID || "cloudflare",
      publicURL,
      site: this.env.SITE || undefined,
      operatorPk: this.env.OPERATOR_PK || undefined,
      seeds: list(this.env.SEEDS),
      witnesses: list(this.env.WITNESSES),
      turn: this.offersTURN(),
      stun: [STUN],
      commitIntervalMs: this.env.COMMIT_INTERVAL_MS ? Number(this.env.COMMIT_INTERVAL_MS) : undefined,
    });
    if (started.error) throw new Error(`the node didn't start: ${started.error}`);
    console.log(`convo node ${started.nodePk} at ${publicURL}`);
    this.reactor = reactor;
    return reactor;
  }

  offersTURN() { return !!(this.env.CLOUDFLARE_TURN_KEY_ID && this.env.CLOUDFLARE_TURN_API_TOKEN); }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const reactor = this.start(url.origin);
    const headers = {};
    for (const [name, value] of request.headers) headers[name.toLowerCase()] = value;
    const body = request.method === "POST" ? await readCapped(request, MAX_BODY) : new Uint8Array(0);
    if (body === null) return new Response("too large", { status: 413, headers: CORS });
    let answer;
    try {
      answer = reactor.call("convo_node_handle", {
        method: request.method,
        path: url.pathname + url.search,
        headers,
        body: base64(body),
        // IPv6 bracketed, so its port is never mistaken for a group (the node limits a /64 as one client).
        peer: ((ip) => (ip.includes(":") ? `[${ip}]` : ip) + ":0")(request.headers.get("CF-Connecting-IP") || "0.0.0.0"),
      });
    } catch (error) {
      // A trap leaves the instance's memory untrustworthy: start again from
      // SQLite on the next request.
      this.reactor = null;
      console.log(`the node trapped on ${request.method} ${url.pathname}: ${error}`);
      return new Response("the node failed", { status: 500, headers: CORS });
    }
    reactor.logs();
    this.sendAll(answer.outbound);
    // §21: the node answered /ice (its rate limit, its STUN); a client it
    // let through gets a TURN credential of its own, never a shared one.
    if (request.method === "GET" && url.pathname === "/ice" && answer.status === 200 && this.offersTURN()) {
      return this.answerICE(url.searchParams.get("for") || "anon");
    }
    // Anything receipted gets committed on the alarm.
    if (request.method === "POST" && (await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + 60_000);
    }
    return new Response(answer.status === 204 ? null : unbase64(answer.body), {
      status: answer.status,
      headers: { "Content-Type": answer.contentType, ...CORS },
    });
  }

  /** §7, §11: retention, closing the batch when due, witnesses' cosignatures. */
  async alarm() {
    const reactor = this.start(null);
    const now = Date.now();
    const exports = reactor.exports;
    const due = reactor.result(exports.convo_node_alarm(now));
    reactor.logs();
    let requests = due.witness;
    for (let round = 0; round < 2 && requests.length; round++) {
      const replies = await Promise.all(requests.map(async (r) => {
        try {
          const response = await fetch(r.url, { method: "POST", body: unbase64(r.body), headers: { "Content-Type": "application/octet-stream" } });
          return { url: r.url, request: r.body, status: response.status, body: base64(new Uint8Array(await response.arrayBuffer())) };
        } catch (error) {
          console.log(`witness ${r.url} failed: ${error}`);
          return null;
        }
      }));
      requests = reactor.call("convo_node_answers", replies.filter(Boolean));
      reactor.logs();
    }
    await Promise.allSettled(this.sendAll(due.outbound));
    // Again while there's something to finish (open items, a checkpoint short
    // of its quorum); otherwise the next write sets it.
    if (due.pending) await this.ctx.storage.setAlarm(Math.min(due.nextAlarmMs, now + 60_000));
  }

  /** Calls nobody waits for: wakes, fraud gossip, batch bodies. */
  sendAll(outbound) {
    const sends = (outbound || []).map((o) =>
      fetch(o.url, { method: o.method, body: o.body ? unbase64(o.body) : undefined,
                     headers: { "Content-Type": o.url.includes("/v1/") ? "application/octet-stream" : "application/json" } })
        .catch((error) => console.log(`${o.method} ${o.url} failed: ${error}`)));
    if (this.ctx.waitUntil) for (const send of sends) this.ctx.waitUntil(send);
    return sends;
  }

  /** §21: a credential of the client's own from Cloudflare Realtime TURN, and its STUN. */
  async answerICE(client) {
    const response = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${this.env.CLOUDFLARE_TURN_KEY_ID}/credentials/generate-ice-servers`,
      { method: "POST", headers: { Authorization: `Bearer ${this.env.CLOUDFLARE_TURN_API_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({ ttl: TURN_TTL, customIdentifier: client.replace(/[^0-9a-zA-Z_-]/g, "").slice(0, 64) || "anon" }) });
    if (!response.ok) return json({ error: `TURN credentials failed (${response.status})` }, 503);
    const offer = await response.json();
    const entries = Array.isArray(offer.iceServers) ? offer.iceServers : [offer.iceServers];
    // The standard ports only (3478, 5349): the full list broke pairing
    // in testing (ICEProvider.swift says how).
    const standard = (u) => { const port = u.split("?")[0].split(":")[2]; return !port || port === "3478" || port === "5349"; };
    const servers = entries.map((e) => ({ ...e, urls: [].concat(e.urls).filter(standard) })).filter((e) => e.urls.length);
    return json({ iceServers: [...servers, { urls: [STUN] }], ttl: TURN_TTL - 60 });
  }
}

/** The body, or null once it's over `limit` bytes (read no further). */
async function readCapped(request, limit) {
  const declared = Number(request.headers.get("Content-Length"));
  if (declared > limit) return null;
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) { reader.cancel(); return null; }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.length; }
  return out;
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json", ...CORS } });
}

function base64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function unbase64(text) {
  const binary = atob(text || "");
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
