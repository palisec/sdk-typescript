/**
 * Holder mandates: sign a vote and check a published vote file. Votes are gasless EIP-712
 * signatures; weight is the voter's token balance at the proposal's snapshot block.
 */
import { proposalTypedData, tally, voteTypedData, type Tally, type VoteChoice } from "./schema";

export { proposalTypedData, voteTypedData, tally, VOTE_CHOICES, type MandateChange, type MandateEnvelope, type Tally, type VoteChoice } from "./schema";

/** Anything that signs EIP-712 typed data (a viem account or wallet client, ethers via fromEthers). */
export interface MandateSigner {
  address: `0x${string}`;
  signTypedData(td: ReturnType<typeof voteTypedData>): Promise<`0x${string}`>;
}

/** Signs a vote and returns the body for POST /v1/public/mandates/{slug}/proposals/{id}/votes. */
export async function signMandateVote(
  signer: MandateSigner,
  v: { chainId: number; mandate: string; proposalId: string; choice: VoteChoice; snapshotBlock: string | bigint },
): Promise<{ voter: `0x${string}`; choice: VoteChoice; signature: `0x${string}` }> {
  const signature = await signer.signTypedData(voteTypedData(v.chainId, { mandate: v.mandate, proposalId: v.proposalId, choice: v.choice, snapshotBlock: v.snapshotBlock }));
  return { voter: signer.address, choice: v.choice, signature };
}

export interface VoteFileCheck {
  signatures_valid: boolean;
  weights_match_snapshot: boolean;
  invalid: string[];
  tally: Tally;
  matches_published_result: boolean;
}

/**
 * Checks a vote file on its own terms: every signature recovers to its voter for this exact proposal,
 * choice and snapshot block; every weight equals the snapshot balance in the file; and the result
 * recomputes to the published one. Rebuilding the snapshot itself from the chain is the recount script's
 * job (recount-mandate.mjs). Needs viem.
 */
export async function verifyVoteFile(file: {
  chain_id: number;
  mandate: { slug: string; rules: { quorum: string; pass_bps: number } };
  proposal: { id: string; snapshot_block: string; result: Partial<Tally> | null };
  votes: { voter: string; choice: VoteChoice; signature: `0x${string}`; weight: string }[];
  holders_at_snapshot: Record<string, string>;
}): Promise<VoteFileCheck> {
  const { recoverTypedDataAddress } = await import("viem");
  const invalid: string[] = [];
  let weightsOk = true;
  for (const v of file.votes) {
    const td = voteTypedData(file.chain_id, { mandate: file.mandate.slug, proposalId: file.proposal.id, choice: v.choice, snapshotBlock: file.proposal.snapshot_block });
    const signer = await recoverTypedDataAddress({ ...td, signature: v.signature }).catch(() => null);
    if (!signer || signer.toLowerCase() !== v.voter.toLowerCase()) invalid.push(v.voter);
    if ((file.holders_at_snapshot[v.voter.toLowerCase()] ?? "0") !== v.weight) weightsOk = false;
  }
  const t = tally({ rules: file.mandate.rules, votes: file.votes.map((v) => ({ voter: v.voter, choice: v.choice, weight: v.weight })) });
  const r = file.proposal.result;
  const matches = !r || (r.for === t.for && r.against === t.against && r.abstain === t.abstain && r.passed === t.passed);
  return { signatures_valid: invalid.length === 0, weights_match_snapshot: weightsOk, invalid, tally: t, matches_published_result: matches };
}
