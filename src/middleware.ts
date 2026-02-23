import { NextRequest, NextResponse } from "next/server";
import { isAgentRequest, extractToken } from "./detect.js";
import { verifyAgentIDToken } from "./verify.js";
import type { VerifierOptions, AgentIDClaims } from "./types.js";

export type AgentIDMiddlewareOptions = VerifierOptions & {
  /**
   * Optional callback invoked when an agent is detected but carries no
   * valid token. Return a `NextResponse` to override the default 403.
   */
  onUnauthorizedAgent?: (
    request: NextRequest,
    reason: string
  ) => NextResponse | void;
};

/**
 * Headers injected by this proxy into downstream route handlers.
 * They are stripped from the *incoming* request first to prevent spoofing.
 */
const MANAGED_HEADERS = [
  "x-agentid-verified",
  "x-agentid-sub",
  "x-agentid-claims",
] as const;

/**
 * Factory that returns a Next.js proxy function which detects AI-agent
 * traffic and enforces AgentID JWT authentication.
 *
 * @example
 * ```ts
 * // proxy.ts (project root)
 * import { createAgentIDMiddleware } from '@agent-id/nextjs';
 *
 * const agentID = createAgentIDMiddleware({
 *   blockUnauthorizedAgents: true,
 * });
 *
 * export function proxy(request: NextRequest) {
 *   return agentID(request);
 * }
 *
 * export const config = { matcher: '/api/:path*' };
 * ```
 */
export function createAgentIDMiddleware(
  options: AgentIDMiddlewareOptions = {}
) {
  const {
    jwksUrl,
    blockUnauthorizedAgents = true,
    clockTolerance = 30,
    onUnauthorizedAgent,
  } = options;

  return async function agentIDMiddleware(
    request: NextRequest
  ): Promise<NextResponse> {
    // Clone incoming headers so we can safely mutate them.
    const requestHeaders = new Headers(request.headers);

    // ── Security: strip client-supplied AgentID headers ──────────────────
    // Without this, a malicious agent could send x-agentid-verified: true
    // and bypass the check in route handlers.
    for (const name of MANAGED_HEADERS) {
      requestHeaders.delete(name);
    }

    // ── Non-agent traffic ──────────────────────────────────────────────────
    if (!isAgentRequest(requestHeaders)) {
      return NextResponse.next({ request: { headers: requestHeaders } });
    }

    // ── Agent detected — require a valid JWT ───────────────────────────────
    const token = extractToken(requestHeaders);

    if (!token) {
      return unauthorized(
        request,
        requestHeaders,
        'Agent request missing AgentID token. Provide "Authorization: Bearer <token>".',
        blockUnauthorizedAgents,
        onUnauthorizedAgent
      );
    }

    // ── Verify the JWT ─────────────────────────────────────────────────────
    let claims: AgentIDClaims;
    try {
      claims = await verifyAgentIDToken(token, {
        ...(jwksUrl !== undefined && { jwksUrl }),
        clockTolerance,
      });
    } catch (err) {
      // Never surface the raw error to the caller — it might leak internals.
      console.warn(
        "[agent-id] Token verification failed:",
        err instanceof Error ? err.message : String(err)
      );
      return unauthorized(
        request,
        requestHeaders,
        "Invalid or expired AgentID token.",
        blockUnauthorizedAgents,
        onUnauthorizedAgent
      );
    }

    // ── Verified — inject identity into request headers ────────────────────
    // Route handlers read these via getAgentIDResult(request).
    requestHeaders.set("x-agentid-verified", "true");
    requestHeaders.set("x-agentid-sub", claims.sub);
    // Full claims encoded as JSON for type-safe extraction by helpers.
    requestHeaders.set("x-agentid-claims", JSON.stringify(claims));

    return NextResponse.next({ request: { headers: requestHeaders } });
  };
}

// ── Internal helper ──────────────────────────────────────────────────────────

function unauthorized(
  request: NextRequest,
  requestHeaders: Headers,
  message: string,
  block: boolean,
  onUnauthorized: AgentIDMiddlewareOptions["onUnauthorizedAgent"]
): NextResponse {
  if (onUnauthorized) {
    const custom = onUnauthorized(request, message);
    if (custom) return custom;
  }

  if (block) {
    return NextResponse.json(
      { error: "AGENT_UNAUTHORIZED", message },
      { status: 403 }
    );
  }

  // Pass through with a "not verified" marker so route handlers can still
  // distinguish agent traffic from human traffic.
  requestHeaders.set("x-agentid-verified", "false");
  return NextResponse.next({ request: { headers: requestHeaders } });
}
