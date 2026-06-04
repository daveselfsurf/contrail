import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import {
  createTrustedGatewayMiddleware,
  TRUSTED_GATEWAY_SECRET_HEADER,
  TRUSTED_GATEWAY_DID_HEADER,
  type ServiceAuth,
} from "../src/core/spaces/auth";

const SECRET = "super-secret-gateway-token";
const DID = "did:plc:alice";

function makeApp(secret = SECRET): Hono {
  const app = new Hono();
  app.use("/xrpc/*", createTrustedGatewayMiddleware(secret));
  app.get("/xrpc/test.method", (c) => {
    const sa = c.get("serviceAuth") as ServiceAuth;
    return c.json({ issuer: sa.issuer, lxm: sa.lxm });
  });
  return app;
}

function call(app: Hono, headers: Record<string, string>): Promise<Response> {
  return app.fetch(new Request("http://localhost/xrpc/test.method", { headers }));
}

describe("trusted-gateway middleware", () => {
  it("accepts a valid secret + DID and sets issuer = asserted DID", async () => {
    const res = await call(makeApp(), {
      [TRUSTED_GATEWAY_SECRET_HEADER]: SECRET,
      [TRUSTED_GATEWAY_DID_HEADER]: DID,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.issuer).toBe(DID);
    expect(body.lxm).toBe("test.method");
  });

  it("rejects a missing secret", async () => {
    const res = await call(makeApp(), { [TRUSTED_GATEWAY_DID_HEADER]: DID });
    expect(res.status).toBe(401);
  });

  it("rejects a wrong secret", async () => {
    const res = await call(makeApp(), {
      [TRUSTED_GATEWAY_SECRET_HEADER]: "wrong",
      [TRUSTED_GATEWAY_DID_HEADER]: DID,
    });
    expect(res.status).toBe(401);
  });

  it("rejects a valid secret with a missing DID", async () => {
    const res = await call(makeApp(), { [TRUSTED_GATEWAY_SECRET_HEADER]: SECRET });
    expect(res.status).toBe(401);
  });

  it("rejects a valid secret with a non-DID principal", async () => {
    const res = await call(makeApp(), {
      [TRUSTED_GATEWAY_SECRET_HEADER]: SECRET,
      [TRUSTED_GATEWAY_DID_HEADER]: "not-a-did",
    });
    expect(res.status).toBe(401);
  });

  it("rejects malformed DIDs that only have the did: prefix", async () => {
    // The old startsWith("did:") check would have wrongly accepted these.
    for (const bad of ["did:", "did:plc:", "did:plc"]) {
      const res = await call(makeApp(), {
        [TRUSTED_GATEWAY_SECRET_HEADER]: SECRET,
        [TRUSTED_GATEWAY_DID_HEADER]: bad,
      });
      expect(res.status, `expected 401 for ${JSON.stringify(bad)}`).toBe(401);
    }
  });

  it("accepts a did:web with extra colons in the method-specific id", async () => {
    const res = await call(makeApp(), {
      [TRUSTED_GATEWAY_SECRET_HEADER]: SECRET,
      [TRUSTED_GATEWAY_DID_HEADER]: "did:web:example.com:user:alice",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.issuer).toBe("did:web:example.com:user:alice");
  });

  it("throws when constructed with an empty secret", () => {
    expect(() => createTrustedGatewayMiddleware("")).toThrow();
  });
});
