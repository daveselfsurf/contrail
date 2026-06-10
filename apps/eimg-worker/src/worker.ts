/**
 * wumblr ephemeral encrypted image (eimg) spaces worker.
 *
 * A spaces-only contrail deployment that backs freeq's `/api/v1/eimg` endpoints:
 * a blind ciphertext store. freeq encrypts images client-side and forwards only
 * ciphertext here; this worker never sees plaintext or keys.
 *
 * Differences from contrail's stock `createWorker`:
 *  - injects an `R2BlobAdapter(env.BLOBS)` per request (the stock worker can't
 *    reach `env` where the module-level config is built);
 *  - authenticates freeq via the trusted-gateway shared secret
 *    (`env.EIMG_GATEWAY_SECRET`) rather than service-auth JWTs;
 *  - the `scheduled` cron runs the **ephemeral blob GC** (`gcExpiredBlobs` per
 *    space) instead of firehose record ingestion (we index nothing public).
 *
 * Bindings (wrangler.jsonc):
 *  - `DB`     — D1 database (spaces metadata: spaces_blobs, members, …)
 *  - `BLOBS`  — R2 bucket (ciphertext bytes; also has a 24h object-lifecycle
 *               rule as an independent deletion backstop)
 *  - `EIMG_GATEWAY_SECRET` — secret shared with freeq-server
 */
import {
  Contrail,
  R2BlobAdapter,
  HostedAdapter,
  gcExpiredBlobs,
  createTrustedGatewayMiddleware,
  type ContrailConfig,
  type R2BucketLike,
  type Database,
} from "@atmo-dev/contrail";

interface Env {
  DB: Database;
  BLOBS: R2BucketLike;
  EIMG_GATEWAY_SECRET: string;
}

/** 24h, matching the R2 lifecycle rule + freeq's read-time expiry. */
const BLOB_TTL_MS = 24 * 60 * 60 * 1000;

/** The space type + namespace must match freeq-server's FREEQ_EIMG_* config
 *  (defaults: namespace com.wumblr.eimg, space type com.wumblr.eimg.space). */
const NAMESPACE = "com.wumblr.eimg";
const SPACE_TYPE = "com.wumblr.eimg.space";

/** Build the spaces-only config, injecting the R2 blob adapter from env.
 *  Called per request/cron because the R2 binding only exists on `env`. */
function buildConfig(env: Env): ContrailConfig {
  return {
    namespace: NAMESPACE,
    // No public collections — this deployment only stores private space blobs.
    collections: {},
    spaces: {
      type: SPACE_TYPE,
      // serviceDid is unused on the trusted-gateway path (no JWT aud check),
      // but the config requires a value; use the deployment's did:web.
      serviceDid: "did:web:eimg.wumblr.com",
      blobs: {
        adapter: new R2BlobAdapter(env.BLOBS),
        // Ephemeral: stamp expires_at = createdAt + 24h; GC + getBlob honor it.
        blobTtlMs: BLOB_TTL_MS,
        // Match freeq's 10MB upload cap; images only.
        maxSize: 10 * 1024 * 1024,
        accept: ["image/png", "image/jpeg", "image/gif", "image/webp", "application/octet-stream"],
      },
    },
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!env.EIMG_GATEWAY_SECRET) {
      return new Response("eimg worker misconfigured: missing EIMG_GATEWAY_SECRET", {
        status: 500,
      });
    }
    const config = buildConfig(env);
    const contrail = new Contrail({ ...config, db: env.DB });
    await contrail.init(env.DB);

    // Auth: freeq presents the shared secret + the acting user's DID. Contrail
    // treats that DID as the request principal.
    const handle = contrail.handler({
      db: env.DB,
      spaces: { authMiddleware: createTrustedGatewayMiddleware(env.EIMG_GATEWAY_SECRET) },
    });
    return await handle(request);
  },

  /** Cron (every minute): reap blobs whose 24h TTL has passed, per space.
   *  Belt-and-suspenders with the R2 object-lifecycle rule. */
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const config = buildConfig(env);
    const blobs = new R2BlobAdapter(env.BLOBS);
    const storage = new HostedAdapter(env.DB, config);
    const now = Date.now();

    ctx.waitUntil(
      (async () => {
        // Enumerate every space and GC its expired blobs. Spaces are paginated;
        // drain the cursor so no space is skipped.
        let cursor: string | undefined;
        let totalDeleted = 0;
        do {
          const { spaces, cursor: next } = await storage.listSpaces({ type: SPACE_TYPE, cursor });
          for (const space of spaces) {
            const res = await gcExpiredBlobs(storage, blobs, space.uri, { now });
            totalDeleted += res.deleted;
          }
          cursor = next;
        } while (cursor);
        if (totalDeleted > 0) {
          console.log(`eimg GC: reaped ${totalDeleted} expired blob(s)`);
        }
      })(),
    );
  },
};
