/**
 * Move per-source TruffleHog config off `projects` into `trufflehog_scan_profiles`.
 *
 * Entrypoint order matters, and here it is the whole point: this runs
 * IMMEDIATELY BEFORE `prisma db push`, not after. The push carries
 * `--accept-data-loss` and will DROP `trufflehog_github_org`,
 * `trufflehog_github_repos` and `trufflehog_only_verified` without prompting —
 * so anything that wants to read them has to do it first. Run it after the push
 * and every existing project's TruffleHog configuration is already gone.
 *
 * Raw SQL only: at this point the database still has the OLD schema while the
 * generated Prisma client has the NEW one, so typed queries would not match.
 *
 * Idempotent and safe on every path:
 *   - fresh install (no `projects` table yet)      -> no-op, push creates it all
 *   - already migrated (legacy columns dropped)    -> no-op
 *   - interrupted half-way                         -> ON CONFLICT DO NOTHING
 *
 * Fails CLOSED. If the migration cannot complete, the process exits non-zero so
 * the entrypoint never reaches `db push`; the legacy columns (and the operator's
 * configuration) survive, the container restarts, and it tries again.
 */
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function tableExists(name) {
  const rows = await prisma.$queryRawUnsafe(
    `SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1 LIMIT 1`,
    name,
  )
  return rows.length > 0
}

async function columnExists(table, column) {
  const rows = await prisma.$queryRawUnsafe(
    `SELECT 1 FROM information_schema.columns
      WHERE table_schema='public' AND table_name=$1 AND column_name=$2 LIMIT 1`,
    table, column,
  )
  return rows.length > 0
}

async function main() {
  // A brand-new database has no `projects` table; the push creates the whole
  // schema and there is nothing to carry over.
  if (!(await tableExists('projects'))) {
    console.log('[trufflehog-migrate] fresh database, nothing to migrate')
    return
  }

  // The legacy columns are the migration's input. Once the push has dropped
  // them the work is done and this can never run again meaningfully.
  const hasLegacy = await columnExists('projects', 'trufflehog_github_org')
  if (!hasLegacy) {
    console.log('[trufflehog-migrate] already migrated')
    return
  }

  console.log('[trufflehog-migrate] moving TruffleHog config into scan profiles...')

  // The table has to exist BEFORE the data moves, and `db push` (which would
  // create it) is the same operation that drops the source columns — so it is
  // created here, matching the Prisma model exactly. The push then finds it
  // already correct and only performs the drops.
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS trufflehog_scan_profiles (
      id          text PRIMARY KEY,
      project_id  text NOT NULL,
      source      text NOT NULL,
      label       text NOT NULL DEFAULT '',
      config      jsonb NOT NULL DEFAULT '{}',
      created_at  timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at  timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`)
  await prisma.$executeRawUnsafe(
    `CREATE UNIQUE INDEX IF NOT EXISTS "trufflehog_scan_profiles_project_id_source_key"
       ON trufflehog_scan_profiles (project_id, source)`)
  await prisma.$executeRawUnsafe(
    `CREATE INDEX IF NOT EXISTS "trufflehog_scan_profiles_project_id_idx"
       ON trufflehog_scan_profiles (project_id)`)
  await prisma.$executeRawUnsafe(
    `ALTER TABLE trufflehog_scan_profiles
       DROP CONSTRAINT IF EXISTS "trufflehog_scan_profiles_project_id_fkey"`)
  await prisma.$executeRawUnsafe(
    `ALTER TABLE trufflehog_scan_profiles
       ADD CONSTRAINT "trufflehog_scan_profiles_project_id_fkey"
       FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE ON UPDATE CASCADE`)

  // The replacement for trufflehog_only_verified. Added here rather than by the
  // push so the UPDATE below has somewhere to write.
  await prisma.$executeRawUnsafe(
    `ALTER TABLE projects ADD COLUMN IF NOT EXISTS trufflehog_result_types text
       NOT NULL DEFAULT 'verified,unverified,unknown'`)

  // One github profile per project that actually had a target configured. The
  // unique index makes a repeat run a no-op instead of a duplicate.
  const inserted = await prisma.$executeRawUnsafe(`
    INSERT INTO trufflehog_scan_profiles (id, project_id, source, label, config, created_at, updated_at)
    SELECT
      md5(random()::text || clock_timestamp()::text || id),
      id,
      'github',
      'Migrated from project settings',
      jsonb_build_object(
        'orgs',  to_jsonb(ARRAY(SELECT trim(x) FROM unnest(string_to_array(coalesce(trufflehog_github_org, ''),   ',')) AS x WHERE trim(x) <> '')),
        'repos', to_jsonb(ARRAY(SELECT trim(x) FROM unnest(string_to_array(coalesce(trufflehog_github_repos, ''), ',')) AS x WHERE trim(x) <> ''))
      ),
      now(), now()
    FROM projects
    WHERE coalesce(trufflehog_github_org, '') <> ''
       OR coalesce(trufflehog_github_repos, '') <> ''
    ON CONFLICT (project_id, source) DO NOTHING`)

  // "Only verified" was a boolean; it becomes a result-type filter.
  let updated = 0
  if (await columnExists('projects', 'trufflehog_only_verified')) {
    updated = await prisma.$executeRawUnsafe(
      `UPDATE projects SET trufflehog_result_types = 'verified'
         WHERE trufflehog_only_verified = true`)
  }

  console.log(
    `[trufflehog-migrate] created ${inserted} profile(s), ` +
    `set ${updated} project(s) to verified-only`)
}

main()
  .catch(e => {
    // Fail closed: exiting non-zero stops the entrypoint before `db push`, so
    // the legacy columns and the operator's configuration survive to be retried
    // on the next container start.
    console.error('[trufflehog-migrate] FAILED, refusing to continue to db push:', e)
    process.exitCode = 1
  })
  .finally(async () => { await prisma.$disconnect() })
