/**
 * JWT claims present in every AgentID token.
 *
 * The `sub` field is a pseudonymous identifier derived via HMAC-SHA256 of the
 * user's BankID personal number. It is stable per person but non-reversible —
 * organisations cannot extract the personal number from it.
 */
export interface AgentIDClaims {
  /** Pseudonymous, stable per-user identifier (HMAC-SHA256 of personal number). */
  sub: string;
  /** Issuer — always "agentid". */
  iss: string;
  /** Issued-at Unix timestamp. */
  iat: number;
  /** Expiry Unix timestamp (1 hour after iat). */
  exp: number;
  /** Unique JWT ID — enables token logging / replay detection on your side. */
  jti: string;
  /** Authentication method — always "bankid" in this version. */
  auth_method: "bankid";
}

export interface AgentIDVerified {
  verified: true;
  claims: AgentIDClaims;
}

export interface AgentIDUnverified {
  verified: false;
  /** Why verification was skipped or failed. */
  reason: "not_agent" | "no_token" | "invalid_token";
}

/** Result attached to every request processed by the AgentID middleware. */
export type AgentIDResult = AgentIDVerified | AgentIDUnverified;

export interface VerifierOptions {
  /**
   * URL of the AgentID JWKS endpoint.
   * Must use HTTPS (except `localhost` / `127.0.0.1` in development).
   *
   * @default 'https://agentidapp.vercel.app/api/jwks'
   */
  jwksUrl?: string;

  /**
   * Block agent requests that carry no valid AgentID token.
   * When `false` the middleware still runs but sets an unverified result
   * on the request instead of returning 403.
   *
   * @default true
   */
  blockUnauthorizedAgents?: boolean;

  /**
   * Allowed clock skew in seconds when verifying JWT expiry.
   * Protects against minor clock drift between issuer and verifier.
   *
   * @default 30
   */
  clockTolerance?: number;
}
