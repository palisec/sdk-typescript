# @palisec/sdk

[![CI](https://github.com/palisec/sdk-typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/palisec/sdk-typescript/actions/workflows/ci.yml) [![npm](https://img.shields.io/npm/v/@palisec/sdk)](https://www.npmjs.com/package/@palisec/sdk) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

TypeScript client for [Palisec](https://palisec.tech): your agent asks before every transaction and sends only on ALLOW.

## Install

```bash
npm install @palisec/sdk viem
# or: pnpm add @palisec/sdk viem
# or: yarn add @palisec/sdk viem
```

Alternative, straight from palisec.tech: `npm install https://palisec.tech/sdk/palisec-sdk-0.6.2.tgz viem`.

Node 18 or later, ESM. `viem` is a peer dependency; ethers v6 works through `fromEthers`.

## Minimal example

```ts
import { createPalisec, PalisecDeniedError } from "@palisec/sdk";

// Server-side only. A ps_live_ key is Robinhood Chain mainnet (4663); a ps_test_ key is testnet (46630).
const palisec = createPalisec({ apiKey: process.env.PALISEC_API_KEY! });

// The SDK enforces the decision: it sends with your viem wallet only on ALLOW.
try {
  const { operation, hash } = await palisec.sendTransaction(walletClient, { to: token, data: transferCalldata, gasLimit: 90_000 });
  if (!hash) console.log("Waiting for a human approver:", operation.operationId);
} catch (e) {
  if (e instanceof PalisecDeniedError) console.warn(e.code, e.message); // nothing was sent
  else throw e;
}
```

## What is in it

- `authorize(intent)` records a decision and returns `ALLOW`, `DENY` or `REQUIRES_HUMAN_SIGNATURE`. Safe to retry: the request ID is the idempotency key.
- `evaluate(intent)` is a dry run that reserves nothing.
- `executeWithSmartAccount(agentKey, intent)` authorizes, has PALISEC co-sign, and submits through a PALISEC smart account, so the agent cannot skip the check on chain.
- `fromEthers(signer)` adapts an ethers v6 signer (checks its network). A wallet on another chain, or another account than the agent's, is refused before sending.
- `waitForApproval(id)`, `getOperation(id)`, `cancel(id)` (withdraws a pending approval).
- `createPalisecTools(client)` gives the OpenAI Agents SDK, the Vercel AI SDK and LangGraph the same framework-neutral tools.
- `verifyWebhook(secret, rawBody, headers)` checks a webhook's HMAC signature and age.
- `@palisec/sdk/policy` exports the policy schema types, validation and the deterministic local evaluator.
- Errors are `PalisecError` subclasses with a stable `code` (`PS_…`). Retries happen only for network errors, 429 and 5xx, and only on calls that are safe to repeat.
- Log events never contain your API key, request bodies or calldata; `redact()` masks keys in any string.

Agents that send from a plain key are enforced only in their own process; agents with a PALISEC smart account are enforced on chain.

Docs: https://palisec.tech/docs/sdk/typescript

## History

Developed inside [palisec/palisec](https://github.com/palisec/palisec), where its full commit history is.
