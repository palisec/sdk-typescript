import { SCHEMA_VERSIONS, type Policy } from "./types";

export interface ValidationError {
  path: string;
  message: string;
}

const UINT = /^(0|[1-9][0-9]{0,77})$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SELECTOR = /^0x[0-9a-fA-F]{8}$/;
const POLICY_ID = /^[a-z0-9_]{3,64}$/;
const MAX_ALLOWLIST = 256;
const MAX_SELECTORS = 64;
const MAX_LOSS_ADDRESSES = 16;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Validates a policy document against schema 1.0 to 1.5. Unknown fields are rejected so a
 * typo can never silently disable a rule. Returns an empty array when valid.
 */
export function validatePolicy(doc: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  const err = (path: string, message: string) => errors.push({ path, message });

  const fields = (o: Obj, path: string, allowed: string[]) => {
    for (const k of Object.keys(o)) if (!allowed.includes(k)) err(`${path}.${k}`, "unknown field");
  };
  const obj = (o: Obj, key: string, path: string): Obj | null => {
    const v = o[key];
    if (!isObj(v)) {
      err(`${path}.${key}`, "required object");
      return null;
    }
    return v;
  };
  const uint = (o: Obj, key: string, path: string) => {
    const v = o[key];
    if (typeof v !== "string" || !UINT.test(v)) err(`${path}.${key}`, "must be a non-negative integer string");
  };
  const int = (o: Obj, key: string, path: string, min: number, max: number) => {
    const v = o[key];
    if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max)
      err(`${path}.${key}`, `must be an integer between ${min} and ${max}`);
  };
  const bool = (o: Obj, key: string, path: string) => {
    if (typeof o[key] !== "boolean") err(`${path}.${key}`, "must be a boolean");
  };
  const address = (v: unknown, path: string) => {
    if (typeof v !== "string" || !ADDRESS.test(v)) err(path, "must be a 20-byte hex address");
  };

  if (!isObj(doc)) return [{ path: "$", message: "policy must be an object" }];
  const $ = "$";
  fields(doc, $, [
    "schema_version", "policy_id", "version", "account", "status",
    "limits", "cooldowns", "contracts", "human_approval", "failure_mode", "asset_safety", "upoch_recovery", "loss_limit", "proven_record", "token_spend",
  ]);

  if (!(SCHEMA_VERSIONS as readonly unknown[]).includes(doc.schema_version)) err("$.schema_version", 'must be "1.0", "1.1", "1.2", "1.3", "1.4" or "1.5"');
  if (typeof doc.policy_id !== "string" || !POLICY_ID.test(doc.policy_id))
    err("$.policy_id", "must be 3-64 chars of a-z, 0-9, _");
  int(doc, "version", $, 1, 2 ** 31 - 1);
  if (!["draft", "active", "disabled"].includes(doc.status as string))
    err("$.status", 'must be "draft", "active" or "disabled"');
  if (doc.failure_mode !== "closed") err("$.failure_mode", 'must be "closed"; fail-open is not supported');

  const account = obj(doc, "account", $);
  if (account) {
    fields(account, "$.account", ["chain_id", "address"]);
    int(account, "chain_id", "$.account", 1, 2 ** 31 - 1);
    address(account.address, "$.account.address");
  }

  const limits = obj(doc, "limits", $);
  if (limits) {
    fields(limits, "$.limits", [
      "max_transaction_value_wei", "max_gas_cost_wei", "hourly_budget_usd_micros",
      "max_pending_operations", "max_price_age_seconds",
    ]);
    uint(limits, "max_transaction_value_wei", "$.limits");
    uint(limits, "max_gas_cost_wei", "$.limits");
    uint(limits, "hourly_budget_usd_micros", "$.limits");
    int(limits, "max_pending_operations", "$.limits", 0, 1000);
    int(limits, "max_price_age_seconds", "$.limits", 1, 3600);
  }

  const cooldowns = obj(doc, "cooldowns", $);
  if (cooldowns) {
    fields(cooldowns, "$.cooldowns", ["identical_calldata_seconds", "identical_intent_seconds"]);
    int(cooldowns, "identical_calldata_seconds", "$.cooldowns", 0, 86400);
    int(cooldowns, "identical_intent_seconds", "$.cooldowns", 0, 86400);
  }

  const contracts = obj(doc, "contracts", $);
  if (contracts) {
    fields(contracts, "$.contracts", ["default", "allowlist", "denylist"]);
    if (contracts.default !== "deny") err("$.contracts.default", 'must be "deny"');
    const list = contracts.allowlist;
    if (!Array.isArray(list)) err("$.contracts.allowlist", "required array");
    else {
      if (list.length > MAX_ALLOWLIST) err("$.contracts.allowlist", `at most ${MAX_ALLOWLIST} entries`);
      list.forEach((entry, i) => {
        const p = `$.contracts.allowlist[${i}]`;
        if (!isObj(entry)) return err(p, "must be an object");
        fields(entry, p, ["address", "selectors", "require_verified_code"]);
        address(entry.address, `${p}.address`);
        bool(entry, "require_verified_code", p);
        if (!Array.isArray(entry.selectors)) err(`${p}.selectors`, "required array");
        else {
          if (entry.selectors.length > MAX_SELECTORS) err(`${p}.selectors`, `at most ${MAX_SELECTORS} selectors`);
          entry.selectors.forEach((s, j) => {
            if (typeof s !== "string" || !SELECTOR.test(s)) err(`${p}.selectors[${j}]`, "must be a 4-byte hex selector");
          });
        }
      });
    }
    const deny = contracts.denylist;
    if (!Array.isArray(deny)) err("$.contracts.denylist", "required array");
    else deny.forEach((a, i) => address(a, `$.contracts.denylist[${i}]`));
  }

  const human = obj(doc, "human_approval", $);
  if (human) {
    fields(human, "$.human_approval", ["usd_threshold_micros", "require_for_unknown_methods"]);
    uint(human, "usd_threshold_micros", "$.human_approval");
    bool(human, "require_for_unknown_methods", "$.human_approval");
  }

  if (doc.asset_safety !== undefined) {
    if (doc.schema_version !== "1.1" && doc.schema_version !== "1.2" && doc.schema_version !== "1.3" && doc.schema_version !== "1.4" && doc.schema_version !== "1.5") err("$.asset_safety", 'requires schema_version "1.1" or later');
    const safety = obj(doc, "asset_safety", $);
    if (safety) {
      const p = "$.asset_safety";
      fields(safety, p, [
        "enabled", "max_transfer_tax_bps", "max_slippage_bps", "require_sell_simulation",
        "block_unlimited_approvals", "on_simulation_unavailable", "max_simulation_age_seconds",
      ]);
      bool(safety, "enabled", p);
      int(safety, "max_transfer_tax_bps", p, 0, 10000);
      int(safety, "max_slippage_bps", p, 0, 10000);
      bool(safety, "require_sell_simulation", p);
      bool(safety, "block_unlimited_approvals", p);
      if (safety.on_simulation_unavailable !== "deny" && safety.on_simulation_unavailable !== "review")
        err(`${p}.on_simulation_unavailable`, 'must be "deny" or "review"');
      int(safety, "max_simulation_age_seconds", p, 1, 300);
    }
  }

  if (doc.upoch_recovery !== undefined) {
    if (doc.schema_version !== "1.2" && doc.schema_version !== "1.3" && doc.schema_version !== "1.4" && doc.schema_version !== "1.5") err("$.upoch_recovery", 'requires schema_version "1.2" or later');
    const up = obj(doc, "upoch_recovery", $);
    if (up) {
      const p = "$.upoch_recovery";
      fields(up, p, ["require_upoch_recoverable", "max_checkpoint_age_seconds", "require_guardian", "on_unavailable"]);
      bool(up, "require_upoch_recoverable", p);
      int(up, "max_checkpoint_age_seconds", p, 60, 31536000);
      bool(up, "require_guardian", p);
      if (up.on_unavailable !== "deny" && up.on_unavailable !== "review") err(`${p}.on_unavailable`, 'must be "deny" or "review"');
    }
  }

  if (doc.loss_limit !== undefined) {
    if (doc.schema_version !== "1.3" && doc.schema_version !== "1.4" && doc.schema_version !== "1.5") err("$.loss_limit", 'requires schema_version "1.3" or later');
    const loss = obj(doc, "loss_limit", $);
    if (loss) {
      const p = "$.loss_limit";
      fields(loss, p, [
        "enabled", "max_drawdown_bps", "max_loss_usd_micros", "window_seconds", "on_breach", "on_valuation_unavailable",
        "stablecoins", "exit_addresses", "max_exit_slippage_bps", "max_closed_market_price_age_seconds", "reset_epoch",
      ]);
      bool(loss, "enabled", p);
      int(loss, "max_drawdown_bps", p, 0, 10000);
      uint(loss, "max_loss_usd_micros", p);
      if (loss.max_drawdown_bps === 0 && loss.max_loss_usd_micros === "0") err(p, "needs max_drawdown_bps or max_loss_usd_micros above zero");
      int(loss, "window_seconds", p, 3600, 604800);
      if (loss.on_breach !== "pause_risk" && loss.on_breach !== "review") err(`${p}.on_breach`, 'must be "pause_risk" or "review"');
      if (loss.on_valuation_unavailable !== "deny" && loss.on_valuation_unavailable !== "review")
        err(`${p}.on_valuation_unavailable`, 'must be "deny" or "review"');
      for (const key of ["stablecoins", "exit_addresses"]) {
        const list = loss[key];
        if (!Array.isArray(list)) err(`${p}.${key}`, "required array");
        else {
          if (list.length > MAX_LOSS_ADDRESSES) err(`${p}.${key}`, `at most ${MAX_LOSS_ADDRESSES} entries`);
          list.forEach((a, i) => address(a, `${p}.${key}[${i}]`));
        }
      }
      int(loss, "max_exit_slippage_bps", p, 0, 10000);
      int(loss, "max_closed_market_price_age_seconds", p, 0, 604800);
      int(loss, "reset_epoch", p, 0, 2 ** 31 - 1);
    }
  }

  if (doc.proven_record !== undefined) {
    if (doc.schema_version !== "1.4" && doc.schema_version !== "1.5") err("$.proven_record", 'requires schema_version "1.4" or later');
    const pr = obj(doc, "proven_record", $);
    if (pr) {
      const p = "$.proven_record";
      fields(pr, p, ["enabled", "source", "min_verified_hours", "max_record_age_seconds", "unlocked_limits"]);
      bool(pr, "enabled", p);
      if (pr.source !== "zolva") err(`${p}.source`, 'must be "zolva"');
      int(pr, "min_verified_hours", p, 24, 8760);
      int(pr, "max_record_age_seconds", p, 600, 86400);
      const un = obj(pr, "unlocked_limits", p);
      if (un) {
        const q = `${p}.unlocked_limits`;
        fields(un, q, ["max_transaction_value_wei", "hourly_budget_usd_micros"]);
        const limits = doc.limits as Record<string, unknown> | undefined;
        for (const k of ["max_transaction_value_wei", "hourly_budget_usd_micros"]) {
          uint(un, k, q);
          const base = limits && typeof limits === "object" ? limits[k] : undefined;
          if (typeof un[k] === "string" && UINT.test(un[k] as string) && typeof base === "string" && UINT.test(base) && BigInt(un[k] as string) < BigInt(base))
            err(`${q}.${k}`, `must be at least limits.${k}`);
        }
      }
    }
  }

  if (doc.token_spend !== undefined) {
    if (doc.schema_version !== "1.5") err("$.token_spend", 'requires schema_version "1.5"');
    const ts = obj(doc, "token_spend", $);
    if (ts) {
      const p = "$.token_spend";
      fields(ts, p, ["enabled", "max_transaction_usd_micros", "on_price_unavailable", "max_closed_market_price_age_seconds", "require_output_to_account"]);
      bool(ts, "enabled", p);
      uint(ts, "max_transaction_usd_micros", p);
      if (ts.on_price_unavailable !== "deny" && ts.on_price_unavailable !== "review") err(`${p}.on_price_unavailable`, 'must be "deny" or "review"');
      int(ts, "max_closed_market_price_age_seconds", p, 0, 604800);
      bool(ts, "require_output_to_account", p);
    }
  }

  return errors;
}

export function isValidPolicy(doc: unknown): doc is Policy {
  return validatePolicy(doc).length === 0;
}
