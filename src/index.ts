export { createAgentIDMiddleware } from "./middleware.js";
export type { AgentIDMiddlewareOptions } from "./middleware.js";

export { verifyAgentIDToken } from "./verify.js";
export type { VerifyTokenOptions } from "./verify.js";

export { isAgentRequest, extractToken } from "./detect.js";

export type {
  AgentIDClaims,
  AgentIDResult,
  AgentIDVerified,
  AgentIDUnverified,
  VerifierOptions,
} from "./types.js";

// ── App Router helper ────────────────────────────────────────────────────────

import type { NextRequest } from "next/server";
import type { AgentIDResult, AgentIDClaims } from "./types.js";

/**
 * Extract the verified AgentID identity from a Next.js App Router request.
 *
 * This function reads the headers set by `createAgentIDMiddleware`. It must
 * only be called from route handlers that sit behind the proxy.
 *
 * @example
 * ```ts
 * // app/api/data/route.ts
 * import { getAgentIDResult } from '@agent-id/nextjs';
 *
 * export async function GET(request: NextRequest) {
 *   const agent = getAgentIDResult(request);
 *   if (!agent.verified) {
 *     return Response.json({ error: 'Unauthorized' }, { status: 403 });
 *   }
 *   return Response.json({ sub: agent.claims.sub });
 * }
 * ```
 */
export function getAgentIDResult(request: NextRequest): AgentIDResult {
  const verified = request.headers.get("x-agentid-verified");

  if (verified !== "true") {
    return {
      verified: false,
      reason: verified === "false" ? "no_token" : "not_agent",
    };
  }

  const claimsJson = request.headers.get("x-agentid-claims");
  if (!claimsJson) {
    return { verified: false, reason: "invalid_token" };
  }

  try {
    const claims = JSON.parse(claimsJson) as AgentIDClaims;
    return { verified: true, claims };
  } catch {
    return { verified: false, reason: "invalid_token" };
  }
}
