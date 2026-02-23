import { createRemoteJWKSet, jwtVerify } from "jose";
import type { AgentIDClaims } from "./types.js";

const DEFAULT_JWKS_URL = "https://agentidapp.vercel.app/api/jwks";

/**
 * Module-level JWKS cache — one RemoteJWKSet instance per unique URL.
 * jose caches the fetched key material internally; re-fetches when the
 * cache TTL (1 h) expires or a new `kid` is seen.
 */
const jwksSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(rawUrl: string): ReturnType<typeof createRemoteJWKSet> {
  if (!jwksSets.has(rawUrl)) {
    const url = new URL(rawUrl); // throws on malformed URL

    // Security: HTTPS is mandatory to prevent MITM on the public-key fetch.
    // Localhost is whitelisted for local development / CI.
    const isLocal =
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "::1";

    if (url.protocol !== "https:" && !isLocal) {
      throw new Error(
        `[agent-id] jwksUrl must use HTTPS, received: ${rawUrl}`
      );
    }

    jwksSets.set(
      rawUrl,
      createRemoteJWKSet(url, {
        cacheMaxAge: 60 * 60 * 1_000, // 1 hour in ms
      })
    );
  }

  return jwksSets.get(rawUrl)!;
}

export interface VerifyTokenOptions {
  jwksUrl?: string;
  clockTolerance?: number;
}

/**
 * Verify an AgentID JWT and return its decoded claims.
 *
 * Security guarantees
 * ───────────────────
 * • Signature   — RS256, verified against the live JWKS public key.
 * • Algorithm   — strict allowlist `['RS256']`; alg:none and HS256 are
 *                 rejected before signature verification even begins.
 * • Issuer      — must be exactly "agentid".
 * • Expiry      — enforced; configurable clock tolerance (default 30 s).
 * • kid         — jose matches the JWT `kid` header to the JWKS automatically.
 * • auth_method — validated at runtime; must equal "bankid".
 *
 * @throws if the token is invalid, expired, or fails any check.
 */
export async function verifyAgentIDToken(
  token: string,
  options: VerifyTokenOptions = {}
): Promise<AgentIDClaims> {
  const jwksUrl = options.jwksUrl ?? DEFAULT_JWKS_URL;
  const JWKS = getJwks(jwksUrl);

  const { payload } = await jwtVerify(token, JWKS, {
    issuer: "agentid",
    // ↓ Critical — explicit allowlist prevents algorithm-confusion attacks.
    //   Any token claiming alg:"none", alg:"HS256", or anything else is
    //   rejected before signature verification.
    algorithms: ["RS256"],
    clockTolerance: options.clockTolerance ?? 30,
  });

  // Runtime validation of AgentID-specific claims.
  if (payload.auth_method !== "bankid") {
    throw new Error(
      `[agent-id] JWT has invalid auth_method: expected "bankid", got "${
        payload.auth_method ?? "undefined"
      }"`
    );
  }
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new Error("[agent-id] JWT is missing the sub claim");
  }

  return payload as unknown as AgentIDClaims;
}
