import { describe, it, expect } from "vitest";
import { createSqliteDatabase } from "../src/adapters/sqlite";
import { initSchema } from "../src/core/db/schema";
import { resolveConfig } from "../src/core/types";
import type { ContrailConfig } from "../src/core/types";
import { MemoryBlobAdapter } from "../src/core/spaces/blob-adapter";

function config(): ContrailConfig {
  return {
    namespace: "test.mig",
    collections: { photo: { collection: "app.event.photo" } },
    spaces: {
      type: "tools.atmo.event.space",
      serviceDid: "did:web:test.example",
      blobs: { adapter: new MemoryBlobAdapter(), blobTtlMs: 24 * 60 * 60 * 1000 },
    },
  };
}

async function columnNames(db: any, table: string): Promise<string[]> {
  const { results } = await db.prepare(`PRAGMA table_info(${table})`).all<any>();
  return results.map((r: any) => r.name);
}

describe("spaces_blobs expires_at migration", () => {
  it("adds expires_at + index to an existing (pre-ephemeral) spaces_blobs table without throwing", async () => {
    const db = createSqliteDatabase(":memory:");

    // Simulate an OLD deployment: spaces_blobs exists WITHOUT expires_at, and
    // the base indexes exist, but the expires index does not. This is the exact
    // shape that previously made initSchema throw ("no such column: expires_at"
    // when the base CREATE INDEX ran before the ALTER).
    await db
      .prepare(
        `CREATE TABLE spaces_blobs (
           space_uri  TEXT NOT NULL,
           cid        TEXT NOT NULL,
           mime_type  TEXT NOT NULL,
           size       INTEGER NOT NULL,
           author_did TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY (space_uri, cid)
         )`
      )
      .run();
    // Seed a pre-existing row so we can confirm it survives the migration with
    // a NULL expiry (pre-existing rows unaffected).
    await db
      .prepare(
        `INSERT INTO spaces_blobs (space_uri, cid, mime_type, size, author_did, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind("at://did:plc:alice/x/y", "bafold", "image/png", 10, "did:plc:alice", 1)
      .run();

    // Before migration: column absent.
    expect(await columnNames(db, "spaces_blobs")).not.toContain("expires_at");

    // The upgrade path: must NOT throw.
    await expect(initSchema(db, resolveConfig(config()))).resolves.toBeUndefined();

    // After migration: column present, pre-existing row has NULL expiry.
    const cols = await columnNames(db, "spaces_blobs");
    expect(cols).toContain("expires_at");
    const row = await db
      .prepare(`SELECT expires_at FROM spaces_blobs WHERE cid = ?`)
      .bind("bafold")
      .first<any>();
    expect(row.expires_at == null).toBe(true);

    // The expires index now exists.
    const { results: idx } = await db
      .prepare(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='spaces_blobs'`)
      .all<any>();
    expect(idx.map((r: any) => r.name)).toContain("idx_spaces_blobs_expires");
  });

  it("is idempotent: running initSchema twice on a fresh DB does not throw", async () => {
    const db = createSqliteDatabase(":memory:");
    await initSchema(db, resolveConfig(config()));
    await expect(initSchema(db, resolveConfig(config()))).resolves.toBeUndefined();
    expect(await columnNames(db, "spaces_blobs")).toContain("expires_at");
  });
});
