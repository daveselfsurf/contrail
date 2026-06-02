import type { Context, MiddlewareHandler } from "hono";
import { ServiceJwtVerifier } from "@atcute/xrpc-server/auth";
import {
  CompositeDidDocumentResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
  type DidDocumentResolver,
} from "@atcute/identity-resolver";
import type { Did, Nsid } from "@atcute/lexicons";
import type { SpacesConfig } from "./types";
import { readInProcess } from "./in-process";

export { ServiceJwtVerifier };

/** Build a ServiceJwtVerifier from a SpacesConfig, using the configured
 *  resolver or a default PLC+Web composite. */
export function buildVerifier(spaces: SpacesConfig): ServiceJwtVerifier {
  const resolver =
    spaces.resolver ??
    new CompositeDidDocumentResolver({
      methods: {
        plc: new PlcDidDocumentResolver(),
        web: new WebDidDocumentResolver(),
      },
    });
  return new ServiceJwtVerifier({
    serviceDid: spaces.serviceDid as Did,
    resolver,
  });
}

export interface ServiceAuth {
  issuer: string;
  audience: string;
  lxm: string | undefined;
  /** OAuth client_id of the caller, if the JWT carries one. */
  clientId?: string;
}

export interface ServiceAuthOptions {
  serviceDid: Did;
  resolver: DidDocumentResolver;
}

/** Hono middleware that authenticates XRPC requests. Order of precedence:
 *    1. In-process marker (same-module calls; see `core/spaces/in-process.ts`)
 *    2. Authorization: Bearer <JWT> as an atproto service-auth token
 *
 *  On success, attaches the claims to `c.var.serviceAuth`. Expected Nsid is
 *  taken from the route pattern (last segment after `/xrpc/`). */
export function createServiceAuthMiddleware(
  verifier: ServiceJwtVerifier
): MiddlewareHandler {
  return async (c, next) => {
    const lxm = extractLxmFromPath(c);

    const inProcess = readInProcess(c.req.raw);
    if (inProcess) {
      c.set("serviceAuth", {
        issuer: inProcess.did,
        audience: "",
        lxm: lxm ?? undefined,
      } satisfies ServiceAuth);
      await next();
      return;
    }

    const header = c.req.header("Authorization");
    if (!header || !header.startsWith("Bearer ")) {
      return c.json({ error: "AuthRequired", message: "Missing bearer token" }, 401);
    }
    const token = header.slice(7).trim();

    const result = await verifier.verify(token, { lxm });
    if (!result.ok) {
      const err = result.error as { error?: string; description?: string } | undefined;
      return c.json(
        {
          error: "AuthRequired",
          message: err?.description ?? err?.error ?? String(result.error),
        },
        401,
      );
    }

    c.set("serviceAuth", {
      issuer: result.value.issuer,
      audience: result.value.audience,
      lxm: result.value.lxm,
    } satisfies ServiceAuth);

    await next();
  };
}

/** Constant-time string compare to avoid leaking the secret via timing. */
function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  // Always compare against a fixed-length buffer so length itself doesn't
  // short-circuit; mismatched lengths still fail.
  let diff = ab.length ^ bb.length;
  const len = Math.max(ab.length, bb.length);
  for (let i = 0; i < len; i++) {
    diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}

/** Header names for the trusted-gateway auth path. */
export const TRUSTED_GATEWAY_SECRET_HEADER = "x-contrail-gateway-secret";
export const TRUSTED_GATEWAY_DID_HEADER = "x-contrail-gateway-did";

/** Hono middleware for a **trusted gateway** caller.
 *
 *  Use when another first-party service (which has already authenticated the
 *  end user) calls contrail over HTTP on the user's behalf, and you trust that
 *  service. The caller presents a shared secret and asserts the acting user's
 *  DID; contrail treats that DID as the `serviceAuth.issuer`.
 *
 *  This is the network-boundary analogue of the in-process marker: the
 *  in-process path (WeakMap on Request identity) cannot cross a process/network
 *  boundary, so a cross-process trusted caller authenticates with a shared
 *  secret instead. The trust boundary is the gateway service, not the PDS — so
 *  only enable this for callers you operate. For zero-trust / federated callers,
 *  use the service-auth JWT path (`createServiceAuthMiddleware`) instead.
 *
 *  Precedence: in-process marker → shared-secret gateway. Requests without the
 *  gateway secret fall through to 401 (this middleware does not also accept
 *  JWTs; compose explicitly if you need both). */
export function createTrustedGatewayMiddleware(sharedSecret: string): MiddlewareHandler {
  if (!sharedSecret) {
    throw new Error("createTrustedGatewayMiddleware: sharedSecret must be non-empty");
  }
  return async (c, next) => {
    const lxm = extractLxmFromPath(c);

    const inProcess = readInProcess(c.req.raw);
    if (inProcess) {
      c.set("serviceAuth", {
        issuer: inProcess.did,
        audience: "",
        lxm: lxm ?? undefined,
      } satisfies ServiceAuth);
      await next();
      return;
    }

    const presented = c.req.header(TRUSTED_GATEWAY_SECRET_HEADER);
    if (!presented || !timingSafeEqual(presented, sharedSecret)) {
      return c.json({ error: "AuthRequired", message: "Invalid gateway credentials" }, 401);
    }

    const did = c.req.header(TRUSTED_GATEWAY_DID_HEADER);
    if (!did || !did.startsWith("did:")) {
      return c.json(
        { error: "AuthRequired", message: `Missing or invalid ${TRUSTED_GATEWAY_DID_HEADER}` },
        401
      );
    }

    c.set("serviceAuth", {
      issuer: did,
      audience: "",
      lxm: lxm ?? undefined,
    } satisfies ServiceAuth);

    await next();
  };
}

function extractLxmFromPath(c: Context): Nsid | null {
  const path = new URL(c.req.url).pathname;
  const match = path.match(/\/xrpc\/([a-zA-Z0-9.-]+)/);
  return (match?.[1] as Nsid) ?? null;
}

/** Read the service auth claims set by the middleware. Throws if unset. */
export function requireServiceAuth(c: Context): ServiceAuth {
  const auth = c.get("serviceAuth") as ServiceAuth | undefined;
  if (!auth) throw new Error("service auth missing; middleware not attached");
  return auth;
}

/** Out-of-band auth check for handlers that don't always require auth.
 *  Returns claims on success, or null if no valid credentials are present.
 *  Order of precedence: in-process marker → service-auth JWT. */
export async function verifyServiceAuthRequest(
  verifier: ServiceJwtVerifier,
  request: Request,
  lxm?: Nsid | null
): Promise<ServiceAuth | null> {
  const inProcess = readInProcess(request);
  if (inProcess) {
    return {
      issuer: inProcess.did,
      audience: "",
      lxm: lxm ?? undefined,
    };
  }

  const header = request.headers.get("Authorization");
  if (!header || !header.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  const result = await verifier.verify(token, { lxm: lxm ?? null });
  if (!result.ok) return null;
  return {
    issuer: result.value.issuer,
    audience: result.value.audience,
    lxm: result.value.lxm,
  };
}

/** Pull a read-grant invite token off the request — query string `?inviteToken=`
 *  or `Authorization: Bearer atmo-invite:<token>`. Returns the raw token (not
 *  hashed) or null. Routes hash + look up via the adapter. */
export function extractInviteToken(request: Request): string | null {
  const url = new URL(request.url);
  const q = url.searchParams.get("inviteToken");
  if (q) return q.trim();
  const header = request.headers.get("Authorization");
  if (header?.startsWith("Bearer atmo-invite:")) {
    return header.slice("Bearer atmo-invite:".length).trim();
  }
  return null;
}

/** Validate a read-grant invite token against a target spaceUri. Returns true
 *  if the token exists, scopes to this space, has a kind that grants read
 *  (`read` or `read-join`), and is not expired/revoked. */
export async function checkInviteReadGrant(
  adapter: { getInvite(tokenHash: string): Promise<{ spaceUri: string; kind: string; revokedAt: number | null; expiresAt: number | null } | null> },
  rawToken: string,
  spaceUri: string,
  hashFn: (token: string) => Promise<string>
): Promise<boolean> {
  const tokenHash = await hashFn(rawToken);
  const invite = await adapter.getInvite(tokenHash);
  if (!invite) return false;
  if (invite.spaceUri !== spaceUri) return false;
  if (invite.kind !== "read" && invite.kind !== "read-join") return false;
  if (invite.revokedAt != null) return false;
  if (invite.expiresAt != null && invite.expiresAt <= Date.now()) return false;
  return true;
}
