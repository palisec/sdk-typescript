import { describe, expect, it, vi } from "vitest";
import {
  createPalisec,
  PalisecApprovalError,
  PalisecConfigError,
  PalisecDeniedError,
  PalisecError,
  PalisecTimeoutError,
  redact,
  fromEthers,
  verifyWebhook,
  createPalisecTools,
  WebhookVerificationError,
  type LogEvent,
} from "../src/index";

const KEY = `ps_test_${"ab".repeat(24)}`;
const TO = "0x2222222222222222222222222222222222222222" as const;
const ACCOUNT = "0x1111111111111111111111111111111111111111" as const;
const OP_ID = "11111111-2222-3333-4444-555555555555";

const op = (over: Record<string, unknown> = {}) => ({
  operation_id: OP_ID,
  request_id: "r1",
  decision: "ALLOW",
  state: "authorized",
  reason_code: null,
  message: "Authorized.",
  retryable: false,
  policy_id: "p",
  policy_version: 1,
  authorization_id: "ps_auth_x",
  expires_at: new Date(Date.now() + 300_000).toISOString(),
  checks: [],
  dry_run: false,
  details: { account: ACCOUNT },
  ...over,
});

function server(responses: (Response | Error)[]) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const next = responses.shift();
    if (!next) throw new Error("no more responses");
    if (next instanceof Error) throw next;
    return next;
  });
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
}
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("configuration", () => {
  it("rejects malformed keys, unsupported chains and plain HTTP", () => {
    expect(() => createPalisec({ apiKey: "sk_live_x" })).toThrow(PalisecConfigError);
    expect(() => createPalisec({ apiKey: KEY, chainId: 1 as never })).toThrow(/not supported/);
    expect(() => createPalisec({ apiKey: KEY, baseUrl: "http://example.com/api/v1" })).toThrow(/HTTPS/);
    expect(() => createPalisec({ apiKey: KEY, baseUrl: "http://localhost:3000/api/v1", fetch: server([]).fetch })).not.toThrow();
  });

  it("takes the network from the key and refuses a mismatch", () => {
    const LIVE = `ps_live_${"cd".repeat(24)}`;
    expect(createPalisec({ apiKey: KEY }).chainId).toBe(46630);
    expect(createPalisec({ apiKey: LIVE }).chainId).toBe(4663);
    expect(createPalisec({ apiKey: LIVE, chainId: 4663 }).chainId).toBe(4663);
    expect(() => createPalisec({ apiKey: LIVE, chainId: 46630 })).toThrow(/mainnet \(ps_live_\) key/);
    expect(() => createPalisec({ apiKey: KEY, chainId: 4663 })).toThrow(/testnet \(ps_test_\) key/);
    expect(redact(`key ${LIVE} end`)).not.toContain("cdcdcdcdcdcdcdcd");
  });
});

describe("authorize", () => {
  it("sends the request with the key in a header and the request ID as idempotency key", async () => {
    const s = server([json(201, op())]);
    const ps = createPalisec({ apiKey: KEY, fetch: s.fetch });
    const res = await ps.authorize({ to: TO, value: 5n, data: "0xa9059cbb", requestId: "r1" });
    expect(res.decision).toBe("ALLOW");
    expect(res.expiresAt).toBeInstanceOf(Date);
    const { url, init } = s.calls[0]!;
    expect(url).toBe("https://palisec.tech/api/v1/operations");
    const headers = init.headers as Record<string, string>;
    expect(headers.authorization).toBe(`Bearer ${KEY}`);
    expect(headers["idempotency-key"]).toBe("r1");
    const body = JSON.parse(String(init.body));
    expect(body).toMatchObject({ request_id: "r1", chain_id: 46630, to: TO, value_wei: "5", data: "0xa9059cbb", gas_limit: 250000 });
    expect(body).not.toHaveProperty("from");
    expect(url).not.toContain("ps_test_");
  });

  it("returns DENY as a value, not an error", async () => {
    const s = server([json(201, op({ decision: "DENY", state: "denied", reason_code: "PS_BUDGET_001", authorization_id: null, message: "Over budget" }))]);
    const res = await createPalisec({ apiKey: KEY, fetch: s.fetch }).authorize({ to: TO });
    expect(res.decision).toBe("DENY");
    expect(res.reasonCode).toBe("PS_BUDGET_001");
  });

  it("retries 503 and network errors with the same idempotency key, then succeeds", async () => {
    const s = server([json(503, { request_id: "a", error: { code: "PS_STATE_001", message: "down", retryable: true } }), new TypeError("fetch failed"), json(201, op())]);
    const res = await createPalisec({ apiKey: KEY, fetch: s.fetch, maxRetries: 2 }).authorize({ to: TO, requestId: "same" });
    expect(res.decision).toBe("ALLOW");
    expect(s.calls).toHaveLength(3);
    for (const c of s.calls) expect((c.init.headers as Record<string, string>)["idempotency-key"]).toBe("same");
  });

  it("maps API errors to PalisecError with the stable code and does not retry a 409", async () => {
    const s = server([json(409, { request_id: "q", error: { code: "PS_REPLAY_001", message: "request_id already used", retryable: false } })]);
    const err = await createPalisec({ apiKey: KEY, fetch: s.fetch }).authorize({ to: TO }).catch((e) => e);
    expect(err).toBeInstanceOf(PalisecError);
    expect(err).toMatchObject({ code: "PS_REPLAY_001", status: 409, requestId: "q", retryable: false });
    expect(s.calls).toHaveLength(1);
  });

  it("reports a timeout as PalisecTimeoutError", async () => {
    const abort = Object.assign(new Error("timed out"), { name: "TimeoutError" });
    const s = server([abort]);
    const err = await createPalisec({ apiKey: KEY, fetch: s.fetch, maxRetries: 0 }).authorize({ to: TO }).catch((e) => e);
    expect(err).toBeInstanceOf(PalisecTimeoutError);
  });
});

describe("cancel", () => {
  it("is never retried, because it changes state", async () => {
    const s = server([json(503, { error: { code: "PS_STATE_001", message: "down", retryable: true } })]);
    await expect(createPalisec({ apiKey: KEY, fetch: s.fetch }).cancel(OP_ID)).rejects.toBeInstanceOf(PalisecError);
    expect(s.calls).toHaveLength(1);
  });
});

describe("sendTransaction", () => {
  const wallet = () => ({ account: { address: ACCOUNT }, sendTransaction: vi.fn(async () => "0xhash" as `0x${string}`) });

  it("sends only on ALLOW, with the gas the fee was bounded on", async () => {
    const w = wallet();
    const s = server([json(201, op())]);
    const res = await createPalisec({ apiKey: KEY, fetch: s.fetch }).sendTransaction(w, { to: TO, value: 1n });
    expect(res.hash).toBe("0xhash");
    expect(w.sendTransaction).toHaveBeenCalledWith(expect.objectContaining({ to: TO, value: 1n, gas: 21000n }));
  });

  it("never calls the wallet on DENY", async () => {
    const w = wallet();
    const s = server([json(201, op({ decision: "DENY", state: "denied", reason_code: "PS_TARGET_001", authorization_id: null }))]);
    await expect(createPalisec({ apiKey: KEY, fetch: s.fetch }).sendTransaction(w, { to: TO })).rejects.toBeInstanceOf(PalisecDeniedError);
    expect(w.sendTransaction).not.toHaveBeenCalled();
  });

  it("refuses a wallet that is not the agent's registered account", async () => {
    const w = { ...wallet(), account: { address: TO } };
    const s = server([json(201, op())]);
    await expect(createPalisec({ apiKey: KEY, fetch: s.fetch }).sendTransaction(w, { to: TO })).rejects.toBeInstanceOf(PalisecConfigError);
    expect(w.sendTransaction).not.toHaveBeenCalled();
  });

  it("returns a held operation unsent unless asked to wait", async () => {
    const w = wallet();
    const held = op({ decision: "REQUIRES_HUMAN_SIGNATURE", state: "pending_approval", reason_code: "PS_HUMAN_001", authorization_id: null });
    const res = await createPalisec({ apiKey: KEY, fetch: server([json(201, held)]).fetch }).sendTransaction(w, { to: TO });
    expect(res.hash).toBeNull();
    expect(res.operation.state).toBe("pending_approval");
    expect(w.sendTransaction).not.toHaveBeenCalled();
  });

  it("waits for approval, then sends", async () => {
    vi.useFakeTimers();
    const w = wallet();
    const held = op({ decision: "REQUIRES_HUMAN_SIGNATURE", state: "pending_approval", authorization_id: null });
    const approved = op({ decision: "REQUIRES_HUMAN_SIGNATURE", state: "approved", authorization_id: "ps_auth_y" });
    const s = server([json(201, held), json(200, held), json(200, approved)]);
    const p = createPalisec({ apiKey: KEY, fetch: s.fetch }).sendTransaction(w, { to: TO }, { waitForApproval: true });
    await vi.advanceTimersByTimeAsync(6000);
    const res = await p;
    vi.useRealTimers();
    expect(res.hash).toBe("0xhash");
    expect(res.operation.authorizationId).toBe("ps_auth_y");
  });
});

describe("waitForApproval", () => {
  it("throws PalisecApprovalError when rejected", async () => {
    const s = server([json(200, op({ decision: "REQUIRES_HUMAN_SIGNATURE", state: "rejected", authorization_id: null }))]);
    await expect(createPalisec({ apiKey: KEY, fetch: s.fetch }).waitForApproval(OP_ID)).rejects.toBeInstanceOf(PalisecApprovalError);
  });
});

describe("redaction", () => {
  it("masks keys in text and never puts them in log events", async () => {
    expect(redact(`key ${KEY} leaked`)).not.toContain(KEY);
    const events: LogEvent[] = [];
    const s = server([json(201, op())]);
    await createPalisec({ apiKey: KEY, fetch: s.fetch, logger: (e) => events.push(e) }).authorize({ to: TO });
    expect(events.length).toBeGreaterThan(0);
    expect(JSON.stringify(events)).not.toContain(KEY);
  });
});

describe("chain and ethers compatibility", () => {
  it("refuses a viem wallet on another chain before sending", async () => {
    const w = { account: { address: ACCOUNT }, chain: { id: 1 }, sendTransaction: vi.fn(async () => "0xhash" as `0x${string}`) };
    const s = server([json(201, op())]);
    await expect(createPalisec({ apiKey: KEY, fetch: s.fetch }).sendTransaction(w, { to: TO })).rejects.toBeInstanceOf(PalisecConfigError);
    expect(w.sendTransaction).not.toHaveBeenCalled();
  });

  const signer = (chainId: bigint) => ({
    getAddress: vi.fn(async () => ACCOUNT),
    sendTransaction: vi.fn(async () => ({ hash: "0xethers" })),
    provider: { getNetwork: vi.fn(async () => ({ chainId })) },
  });

  it("fromEthers sends with the bounded gas and a pinned chain", async () => {
    const sg = signer(46630n);
    const w = await fromEthers(sg);
    const res = await createPalisec({ apiKey: KEY, fetch: server([json(201, op())]).fetch }).sendTransaction(w, { to: TO, value: 5n, gasLimit: 90_000 });
    expect(res.hash).toBe("0xethers");
    expect(sg.sendTransaction).toHaveBeenCalledWith({ to: TO, value: 5n, data: "0x", gasLimit: 90000n, chainId: 46630n });
  });

  it("fromEthers refuses a signer connected to another network", async () => {
    await expect(fromEthers(signer(1n))).rejects.toBeInstanceOf(PalisecConfigError);
  });

  it("fromEthers keeps the account check: a different signer is refused", async () => {
    const sg = { ...signer(46630n), getAddress: vi.fn(async () => TO) };
    const w = await fromEthers(sg);
    await expect(createPalisec({ apiKey: KEY, fetch: server([json(201, op())]).fetch }).sendTransaction(w, { to: TO })).rejects.toBeInstanceOf(PalisecConfigError);
    expect(sg.sendTransaction).not.toHaveBeenCalled();
  });
});

describe("2.0 additions", () => {
  it("reads identity, policy, audit and own operations from the integration endpoints", async () => {
    const s = server([
      json(200, { agent_id: "a1", name: "bot", framework: "langgraph", status: "active", chain_id: 46630, account: ACCOUNT, scopes: ["policy:read"], policy: { policy_key: "p", version: 2 }, emergency_stop: false }),
      json(200, { policy_key: "p", name: "P", version: 2, document_hash: "ab", activated_at: "2026-11-16T00:00:00Z", document: { schema_version: "1.0" } }),
      json(200, { events: [{ seq: "5", event_id: "e1", type: "operation.allowed", detail: {}, created_at: "2026-11-16T00:00:00Z" }], next_before: null }),
      json(200, { operations: [op()], next_before: null }),
    ]);
    const c = createPalisec({ apiKey: KEY, fetch: s.fetch });
    expect((await c.whoAmI()).framework).toBe("langgraph");
    expect((await c.policy.get()).version).toBe(2);
    expect((await c.audit.list({ limit: 5 })).events[0]!.type).toBe("operation.allowed");
    expect((await c.operations.list({ decision: "ALLOW" })).operations[0]!.decision).toBe("ALLOW");
    expect(s.calls.map((x) => new URL(x.url).pathname)).toEqual(["/api/v1/integration", "/api/v1/integration/policy", "/api/v1/integration/audit-events", "/api/v1/integration/operations"]);
    expect(s.calls[3]!.url).toContain("decision=ALLOW");
  });

  it("transactions.propose is authorize, with the request ID as idempotency key", async () => {
    const s = server([json(201, op())]);
    await createPalisec({ apiKey: KEY, fetch: s.fetch }).transactions.propose({ to: TO, requestId: "r-9" });
    expect(new URL(s.calls[0]!.url).pathname).toBe("/api/v1/operations");
    expect((s.calls[0]!.init.headers as Record<string, string>)["idempotency-key"]).toBe("r-9");
  });

  it("verifies webhook signatures and rejects tampering, stale and missing headers", async () => {
    const secret = "whsec_test";
    const body = JSON.stringify({ id: "e1", type: "ping", created_at: "", organization_id: "o", data: {} });
    const ts = String(Math.floor(Date.now() / 1000));
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${ts}.${body}`))), (b) => b.toString(16).padStart(2, "0")).join("");
    const headers = { "palisec-timestamp": ts, "palisec-signature": `v1=${sig}` };
    expect((await verifyWebhook(secret, body, headers)).type).toBe("ping");
    expect((await verifyWebhook(secret, body, new Headers(headers))).id).toBe("e1");
    await expect(verifyWebhook(secret, body.replace("ping", "pong"), headers)).rejects.toBeInstanceOf(WebhookVerificationError);
    await expect(verifyWebhook("wrong", body, headers)).rejects.toBeInstanceOf(WebhookVerificationError);
    await expect(verifyWebhook(secret, body, headers, { now: Number(ts) + 3600 })).rejects.toBeInstanceOf(WebhookVerificationError);
    await expect(verifyWebhook(secret, body, {})).rejects.toBeInstanceOf(WebhookVerificationError);
  });
});

describe("framework tools", () => {
  const wallet = () => ({ account: { address: ACCOUNT }, sendTransaction: vi.fn(async () => "0xhash" as `0x${string}`) });
  const tx = { to: TO, value_wei: "0", data: "0x", gas_limit: 21000 };

  it("exposes JSON-schema tools; sending only when a wallet is given", () => {
    const names = createPalisecTools(createPalisec({ apiKey: KEY, fetch: server([]).fetch })).map((t) => t.name);
    expect(names).toEqual(["palisec_evaluate_transaction", "palisec_get_operation", "palisec_explain_reason_code"]);
    const withWallet = createPalisecTools(createPalisec({ apiKey: KEY, fetch: server([]).fetch }), { wallet: wallet() });
    expect(withWallet.map((t) => t.name)).toContain("palisec_send_transaction");
    for (const t of withWallet) expect(t.parameters.additionalProperties).toBe(false);
  });

  it("send returns sent, held or denied as text and never sends on DENY", async () => {
    const w = wallet();
    const s = server([json(201, op()), json(201, op({ decision: "REQUIRES_HUMAN_SIGNATURE", state: "pending_approval", authorization_id: null })), json(201, op({ decision: "DENY", state: "denied", reason_code: "PS_TARGET_001", authorization_id: null }))]);
    const send = createPalisecTools(createPalisec({ apiKey: KEY, fetch: s.fetch }), { wallet: w }).find((t) => t.name === "palisec_send_transaction")!;
    expect(JSON.parse(await send.execute(tx)).status).toBe("sent");
    expect(JSON.parse(await send.execute(tx)).status).toBe("held_for_approval");
    const denied = JSON.parse(await send.execute(tx));
    expect(denied).toMatchObject({ status: "denied", code: "PS_TARGET_001" });
    expect(w.sendTransaction).toHaveBeenCalledTimes(1);
  });

  it("invalid model input is reported as text, not thrown, and nothing is called", async () => {
    const s = server([]);
    const ev = createPalisecTools(createPalisec({ apiKey: KEY, fetch: s.fetch }))[0]!;
    expect(JSON.parse(await ev.execute({ ...tx, to: "0x12" }))).toMatchObject({ status: "error", code: "PS_REQUEST_001" });
    expect(s.calls).toHaveLength(0);
  });
});
