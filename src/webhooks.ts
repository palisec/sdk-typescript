/**
 * Verifies a Palisec webhook: `palisec-signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>`.
 * Pass the raw request body exactly as received (before JSON parsing). Rejects stale timestamps
 * (default 5 minutes) so a captured delivery cannot be replayed later, and compares in constant time.
 * Deduplicate on `palisec-event-id`: retries reuse it.
 */
export interface WebhookEvent {
  id: string;
  type: string;
  created_at: string;
  organization_id: string;
  data: Record<string, unknown>;
}

type HeaderBag = Headers | Record<string, string | string[] | undefined>;

function header(h: HeaderBag, name: string): string | null {
  if (typeof (h as Headers).get === "function") return (h as Headers).get(name);
  const v = (h as Record<string, string | string[] | undefined>)[name] ?? (h as Record<string, string | string[] | undefined>)[name.toLowerCase()];
  return Array.isArray(v) ? (v[0] ?? null) : (v ?? null);
}

export class WebhookVerificationError extends Error {
  override readonly name = "WebhookVerificationError";
}

export async function verifyWebhook(secret: string, rawBody: string, headers: HeaderBag, opts: { toleranceSeconds?: number; now?: number } = {}): Promise<WebhookEvent> {
  const ts = header(headers, "palisec-timestamp");
  const sig = header(headers, "palisec-signature");
  if (!ts || !/^\d{1,12}$/.test(ts) || !sig?.startsWith("v1=")) throw new WebhookVerificationError("Missing or malformed Palisec signature headers");
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(ts)) > (opts.toleranceSeconds ?? 300)) throw new WebhookVerificationError("Webhook timestamp is outside the tolerance window");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${ts}.${rawBody}`)));
  const expected = Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("");
  const given = sig.slice(3);
  let diff = given.length ^ expected.length;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ (given.charCodeAt(i) || 0);
  if (diff !== 0) throw new WebhookVerificationError("Webhook signature does not match");
  return JSON.parse(rawBody) as WebhookEvent;
}
