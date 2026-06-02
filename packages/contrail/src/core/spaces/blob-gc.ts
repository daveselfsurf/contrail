import type { BlobAdapter } from "./blob-adapter";
import { blobKey } from "./blob-adapter";
import type { StorageAdapter } from "./types";

export interface BlobGcOptions {
  /** Orphan rows created before this timestamp are eligible for deletion. */
  olderThan: number;
  /** Maximum number of blobs to delete in this pass. Defaults to 500. */
  batchSize?: number;
}

export interface BlobGcResult {
  deleted: number;
  cids: string[];
}

/** Delete blob bytes + metadata for any blob older than `olderThan` that
 *  is not referenced by any record in the space. Safe to run periodically. */
export async function gcOrphanBlobs(
  storage: StorageAdapter,
  blobs: BlobAdapter,
  spaceUri: string,
  options: BlobGcOptions
): Promise<BlobGcResult> {
  const batchSize = options.batchSize ?? 500;
  const orphans = await storage.findOrphanBlobs(spaceUri, options.olderThan, batchSize);
  return deleteBlobRows(storage, blobs, orphans);
}

export interface ExpiredBlobGcOptions {
  /** Absolute wall-clock time (ms epoch). Blobs whose `expires_at <= now` are
   *  deleted. Pass a fixed timestamp for deterministic tests. */
  now: number;
  /** Maximum number of blobs to delete in this pass. Defaults to 500. */
  batchSize?: number;
}

/** Delete blob bytes + metadata for **ephemeral** blobs whose `expires_at` has
 *  passed, regardless of whether they're still referenced. This is the time-
 *  based (TTL) reaper for ephemeral spaces; permanent blobs (NULL expires_at)
 *  are never touched here. Safe to run periodically from a scheduled handler. */
export async function gcExpiredBlobs(
  storage: StorageAdapter,
  blobs: BlobAdapter,
  spaceUri: string,
  options: ExpiredBlobGcOptions
): Promise<BlobGcResult> {
  const batchSize = options.batchSize ?? 500;
  const expired = await storage.findExpiredBlobs(spaceUri, options.now, batchSize);
  return deleteBlobRows(storage, blobs, expired);
}

/** Shared deletion: drop bytes from the blob backend, then clear metadata. */
async function deleteBlobRows(
  storage: StorageAdapter,
  blobs: BlobAdapter,
  rows: { spaceUri: string; cid: string }[]
): Promise<BlobGcResult> {
  if (rows.length === 0) return { deleted: 0, cids: [] };

  const keys: string[] = [];
  for (const row of rows) {
    keys.push(await blobKey(row.spaceUri, row.cid));
  }
  await blobs.delete(keys);
  for (const row of rows) {
    await storage.deleteBlobMeta(row.spaceUri, row.cid);
  }
  return { deleted: rows.length, cids: rows.map((o) => o.cid) };
}
