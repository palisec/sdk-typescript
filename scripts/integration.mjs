#!/usr/bin/env node
/**
 * Runs the built SDK against a live Palisec server with a database:
 *   BASE_URL=http://localhost:3000 node packages/sdk/scripts/integration.mjs
 * Sets up an organization, policy, agent and key through the console API with throwaway wallets,
 * then exercises the SDK. Nothing is broadcast: the wallet is a recording stub.
 */
import { encodeFunctionData, erc20Abi } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createPalisec, PalisecDeniedError, PalisecError } from "../dist/index.js";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
let passed = 0;
let failed = 0;
const check = (name, ok, detail) => {
  ok ? passed++ : failed++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok || detail === undefined ? "" : `  -> ${JSON.stringify(detail).slice(0, 300)}`}`);
};

async function call(method, path, { cookie, body } = {}) {
  const headers = { origin: BASE };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (cookie) headers.cookie = cookie;
  const res = await fetch(`${BASE}/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => ({})), headers: res.headers };
}

const owner = privateKeyToAccount(generatePrivateKey());
const agentWallet = privateKeyToAccount(generatePrivateKey());
const token = privateKeyToAccount(generatePrivateKey()).address;
const c = await call("POST", "/auth/challenges", { body: { address: owner.address, chain_id: 46630 } });
const v = await call("POST", "/auth/verify", { body: { nonce: c.body.nonce, signature: await owner.signMessage({ message: c.body.message }) } });
const cookie = (v.headers.get("set-cookie") ?? "").split(";")[0];

const p = await call("POST", "/policies", { cookie, body: { name: "SDK test", policy_key: "sdk_test", chain_id: 46630, account: agentWallet.address } });
const draft = {
  ...p.body.draft,
  limits: { ...p.body.draft.limits, max_price_age_seconds: 120, max_pending_operations: 10 },
  cooldowns: { identical_calldata_seconds: 0, identical_intent_seconds: 0 },
  contracts: { default: "deny", allowlist: [{ address: token, selectors: ["0xa9059cbb"], require_verified_code: false }], denylist: [] },
  human_approval: { usd_threshold_micros: "1000000000", require_for_unknown_methods: true },
};
const saved = await call("PUT", `/policies/${p.body.id}`, { cookie, body: { document: draft } });
await call("POST", `/policies/${p.body.id}/activate`, { cookie, body: { confirm: true, draft_hash: saved.body.draft_hash } });
const a = await call("POST", "/agents", { cookie, body: { name: "SDK agent", chain_id: 46630, account: agentWallet.address, policy_id: p.body.id } });
const key = (await call("POST", `/agents/${a.body.id}/credentials`, { cookie, body: { label: "sdk" } })).body.secret;
check("setup: agent key issued", /^ps_test_[0-9a-f]{48}$/.test(key ?? ""), key);

const palisec = createPalisec({ apiKey: key, baseUrl: `${BASE}/api/v1` });
const sent = [];
const wallet = { account: { address: agentWallet.address }, sendTransaction: async (tx) => (sent.push(tx), "0x" + "ab".repeat(32)) };
const transfer = (amount) => encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [owner.address, amount] });
const approveCall = encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [owner.address, 1n] });

const dry = await palisec.evaluate({ to: token, data: transfer(1n), gasLimit: 90_000 });
check("evaluate: dry run allows and records nothing", dry.decision === "ALLOW" && dry.dryRun && dry.operationId === null, dry);

// A true retry sends the same body: pin the clock so both calls compute the same deadline (the first can
// take over a second with asset simulation, and a different deadline is, correctly, a different request).
const realNow = Date.now;
const pinned = realNow();
Date.now = () => pinned;
const r1 = await palisec.authorize({ to: token, data: transfer(2n), gasLimit: 90_000, requestId: "sdk-idem-1" });
const r2 = await palisec.authorize({ to: token, data: transfer(2n), gasLimit: 90_000, requestId: "sdk-idem-1" });
Date.now = realNow;
check("authorize: ALLOW with an authorization and expiry", r1.decision === "ALLOW" && r1.authorizationId && r1.expiresAt instanceof Date, r1);
check("authorize: retrying the same request returns the same operation", r1.operationId === r2.operationId, [r1.operationId, r2.operationId]);

const ok = await palisec.sendTransaction(wallet, { to: token, data: transfer(3n), gasLimit: 90_000 });
check("sendTransaction: sends on ALLOW", ok.hash !== null && sent.length === 1 && sent[0].gas === 90000n, ok);

const before = sent.length;
const denied = await palisec.sendTransaction(wallet, { to: owner.address, value: 1n }).catch((e) => e);
check("sendTransaction: DENY throws with a stable code and never sends", denied instanceof PalisecDeniedError && denied.code === "PS_TARGET_001" && sent.length === before, denied?.code);

const held = await palisec.sendTransaction(wallet, { to: token, data: approveCall, gasLimit: 90_000 });
check("sendTransaction: a held operation is returned unsent", held.hash === null && held.operation.state === "pending_approval", held.operation);

const withdrawn = await palisec.cancel(held.operation.operationId);
check("cancel: the agent withdraws its pending approval", withdrawn.state === "cancelled", withdrawn.state);

const held2 = await palisec.authorize({ to: token, data: approveCall, gasLimit: 90_000 });
const waiting = palisec.waitForApproval(held2.operationId, { intervalMs: 1000, timeoutMs: 60_000 });
const list = await call("GET", "/approvals", { cookie });
const item = list.body.approvals.find((x) => x.operation_id === held2.operationId);
const t = item.typed_data;
const message = { ...t.message };
for (const k of ["chainId", "valueWei", "policyVersion", "expiresAt"]) message[k] = BigInt(message[k]);
const signature = await owner.signTypedData({ domain: t.domain, types: { OperationApproval: t.types.OperationApproval }, primaryType: t.primaryType, message });
const approved = await call("POST", `/approvals/${held2.operationId}/approve`, { cookie, body: { signature } });
check("console: approver signs the exact operation", approved.status === 200, approved.body);
const done = await waiting;
check("waitForApproval: resolves once approved, with an authorization", done.state === "approved" && Boolean(done.authorizationId), done);

const me = await palisec.whoAmI();
check("whoAmI: the key identifies its agent and scopes", me.account.toLowerCase() === agentWallet.address.toLowerCase() && me.scopes.includes("mcp"), me);
const bound = await palisec.policy.get();
check("policy.get: the exact active version", bound.version === 1 && bound.document.schema_version === "1.1", bound.version);
const trail = await palisec.audit.list({ limit: 10 });
check("audit.list: the agent's own audit events", trail.events.some((e) => e.type.startsWith("operation.")), trail.events.length);
const prop = await palisec.transactions.propose({ to: token, data: transfer(9n), gasLimit: 90_000 });
const mine = await palisec.operations.list({ limit: 5 });
check("transactions.propose and operations.list", prop.decision === "ALLOW" && mine.operations.some((o) => o.operationId === prop.operationId), prop.decision);

const bad = createPalisec({ apiKey: `ps_test_${"0".repeat(48)}`, baseUrl: `${BASE}/api/v1` });
const authErr = await bad.authorize({ to: token }).catch((e) => e);
check("errors: an unknown key is PS_AUTH_001", authErr instanceof PalisecError && authErr.code === "PS_AUTH_001" && authErr.status === 401, authErr?.code);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
