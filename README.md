# @agent-id/nextjs

Next.js proxy that automatically detects AI-agent traffic and requires a valid [AgentID](https://agentidapp.vercel.app) JWT. Human browser traffic always passes through untouched.

## Install

```bash
npm install @agent-id/nextjs
```

Requires `next >= 16`.

## Setup — 2 steps

### 1. Add the proxy

Create `proxy.ts` in your project root (same level as `app/`):

```ts
import { createAgentIDMiddleware } from '@agent-id/nextjs';
import type { NextRequest } from 'next/server';

const agentID = createAgentIDMiddleware();

export function proxy(request: NextRequest) {
  return agentID(request);
}

// Protect your API routes
export const config = {
  matcher: '/:path*',
};
```

That's it. The proxy now:
- Lets all human browser traffic through unchanged
- Requires a valid AgentID JWT from any AI agent / bot
- Returns `403 AGENT_UNAUTHORIZED` when the JWT is missing or invalid

### 2. Read the verified identity in your route handlers (optional)

```ts
// app/api/anything/route.ts
import { getAgentIDResult } from '@agent-id/nextjs';
import type { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const agent = getAgentIDResult(request);

  if (agent.verified) {
    // Verified AI agent — claims are fully typed
    console.log(agent.claims.sub);          // pseudonymous stable user ID
    console.log(agent.claims.auth_method);  // "bankid"
  }

  // Human traffic: agent.verified === false, agent.reason === 'not_agent'
  return Response.json({ ok: true });
}
```

## How agents authenticate

Agents add one header to every request:

```
Authorization: Bearer <agentid-jwt>
```

The JWT is obtained by completing a BankID flow at [agentidapp.vercel.app](https://agentidapp.vercel.app). Tokens are valid for 1 hour.

## Options

All options are optional — `createAgentIDMiddleware()` with no arguments works out of the box.

```ts
createAgentIDMiddleware({
  // Return 403 when an agent has no valid token (default: true).
  // Set to false to let unverified agents through (useful for logging / gradual rollout).
  blockUnauthorizedAgents: true,

  // Override the JWKS endpoint — only needed if you self-host AgentID.
  jwksUrl: 'https://your-agentid.example.com/api/jwks',

  // Clock skew tolerance in seconds (default: 30).
  clockTolerance: 30,

  // Fully custom response when an agent is rejected.
  onUnauthorizedAgent: (request, reason) =>
    NextResponse.json({ error: 'No AgentID token', reason }, { status: 403 }),
})
```

## What gets verified

Verification is **fully offline** after the first request. The public key is fetched once from the AgentID JWKS endpoint and cached for 1 hour — no per-request network call.

| Check | Requirement |
|---|---|
| Signature | RS256 — `alg:none` and HS256 are explicitly rejected |
| Issuer (`iss`) | Must equal `"agentid"` |
| Expiry (`exp`) | Must be in the future |
| `auth_method` | Must equal `"bankid"` |

## JWT claims

| Field | Description |
|---|---|
| `sub` | Pseudonymous stable user ID (HMAC-SHA256 of BankID personal number — non-reversible, same person always gets the same ID) |
| `auth_method` | Always `"bankid"` |
| `iss` | `"agentid"` |
| `exp` | Unix timestamp — 1 hour from issue |
| `iat` | Unix timestamp — when issued |
| `jti` | Unique token ID |
