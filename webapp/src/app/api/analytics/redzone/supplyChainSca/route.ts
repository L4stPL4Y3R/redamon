import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'

/**
 * Supply-Chain SCA: the Package / MalPackageFinding / Vulnerability model that
 * L1 (standalone SBOM or repo scan) and L2 (live-target recon harvest) both
 * MERGE into. Distinct from the `supplyChain` route, which reads JsReconFinding
 * nodes (source maps, dev comments, dependency confusion) and is surfaced as
 * "JS Dep Signals".
 *
 * Three sheets:
 *   verdicts   - one row per MalPackageFinding (malicious / suspicious / not analysed)
 *   packages   - one row per Package, with rolled-up verdict + advisory counts
 *   advisories - one row per CVE/GHSA Vulnerability written by the OSV pass
 *
 * Every query is tenant-scoped on {project_id: $pid} behind guardProject.
 */

type Neo4jRecord = { get: (key: string) => unknown }

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in (val as object)) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

function toStrList(val: unknown): string[] {
  if (!Array.isArray(val)) return []
  return val.filter(v => v != null).map(v => String(v))
}

// L2 writes the whole artifact once PER BaseURL, so a target with 30 base URLs
// gives every package 30 DEPENDS_ON edges. Anchors are therefore always
// collected (pattern comprehension), never joined row-wise, or one finding
// would fan out into 30 identical rows.
const ANCHORS = `
  [(b:BaseURL)-[:DEPENDS_ON]->(p) WHERE b.project_id = $pid | b.url]        AS baseUrls,
  [(gr:GithubRepository)-[:DEPENDS_ON]->(p) WHERE gr.project_id = $pid | gr.name] AS repos`

const SEV_ORDER = `CASE $sev WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                             WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`

function sevOrder(expr: string): string {
  // split/join, not String.replace: a replacement string treats `$&`, `$'` and
  // `` $` `` as capture-group syntax, so any future expression containing a `$`
  // would be silently rewritten into broken Cypher.
  return SEV_ORDER.split('$sev').join(expr)
}

// A finding is "not analysed" when GuardDog never produced a verdict. The
// soft_error flag is authoritative; the advisory_id fallback keeps rows written
// before that flag was persisted classified correctly instead of showing them
// as ordinary suspicious hits.
const NOT_ANALYSED = `(coalesce(f.soft_error, false) OR coalesce(f.advisory_id, '') = 'guarddog-not-run')`

// Row caps. Exported through meta.truncated so the UI can say "there is more"
// instead of presenting a capped list as the complete picture.
const VERDICT_LIMIT = 1000
const SHEET_LIMIT = 2000

export async function GET(request: NextRequest) {
  const pid = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(pid || '')
  if (__denied) return __denied
  if (!pid) return NextResponse.json({ error: 'projectId is required' }, { status: 400 })

  const session = getGraphSession()
  try {
    // --- verdicts: MalPackageFinding joined to its package + anchors ---------
    const verdicts = await session.run(
      `MATCH (p:Package {project_id: $pid})-[:FLAGGED_AS]->(f:MalPackageFinding {project_id: $pid})
       WITH p, f,${ANCHORS}
       RETURN f.finding_id      AS findingId,
              f.verdict         AS verdict,
              f.severity        AS severity,
              f.source_tool     AS sourceTool,
              f.advisory_id     AS advisoryId,
              f.title           AS title,
              f.detail          AS detail,
              f.confidence      AS confidence,
              coalesce(f.soft_error, false) AS softError,
              coalesce(f.aliases, [])       AS aliases,
              toString(f.first_seen)        AS firstSeen,
              toString(f.last_seen)         AS lastSeen,
              p.purl            AS purl,
              p.name            AS name,
              p.version         AS version,
              p.ecosystem       AS ecosystem,
              p.source          AS harvestSource,
              p.source_path     AS sourcePath,
              baseUrls, repos
       ORDER BY CASE WHEN f.verdict = 'malicious' THEN 0
                     WHEN ${NOT_ANALYSED} THEN 2 ELSE 1 END,
                ${sevOrder('f.severity')},
                p.name
       LIMIT ${VERDICT_LIMIT}`,
      { pid })

    // --- packages: the inventory, with rolled-up verdict counts --------------
    const packages = await session.run(
      `MATCH (p:Package {project_id: $pid})
       WITH p,${ANCHORS},
            [(p)-[:FLAGGED_AS]->(f:MalPackageFinding) WHERE f.project_id = $pid | f] AS findings,
            [(p)-[:HAS_VULNERABILITY]->(v:Vulnerability) WHERE v.project_id = $pid | v] AS vulns
       RETURN p.purl        AS purl,
              p.name        AS name,
              p.version     AS version,
              p.ecosystem   AS ecosystem,
              p.source      AS harvestSource,
              p.source_path AS sourcePath,
              toString(p.first_seen) AS firstSeen,
              toString(p.last_seen)  AS lastSeen,
              baseUrls, repos,
              size([f IN findings WHERE f.verdict = 'malicious']) AS maliciousCount,
              size([f IN findings WHERE f.verdict = 'suspicious'
                    AND NOT (coalesce(f.soft_error, false)
                             OR coalesce(f.advisory_id, '') = 'guarddog-not-run')]) AS suspiciousCount,
              size([f IN findings WHERE coalesce(f.soft_error, false)
                    OR coalesce(f.advisory_id, '') = 'guarddog-not-run'])           AS notAnalysedCount,
              size(vulns)                     AS advisoryCount,
              [v IN vulns | v.severity]       AS advisorySeverities
       ORDER BY maliciousCount DESC, advisoryCount DESC, suspiciousCount DESC, p.name
       LIMIT ${SHEET_LIMIT}`,
      { pid })

    // --- advisories: the CVE/GHSA half, invisible everywhere else ------------
    // v.source = 'osv' is mandatory: Vulnerability is a shared label that GVM,
    // nuclei and the GraphQL scanner also write into.
    const advisories = await session.run(
      `MATCH (p:Package {project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability {project_id: $pid})
       WHERE v.source = 'osv'
       WITH p, v,${ANCHORS}
       RETURN v.id           AS advisoryId,
              v.severity     AS severity,
              v.cvss_metrics AS cvss,
              v.name         AS title,
              v.description  AS description,
              p.purl         AS purl,
              p.name         AS name,
              p.version      AS version,
              p.ecosystem    AS ecosystem,
              p.source       AS harvestSource,
              p.source_path  AS sourcePath,
              toString(v.first_seen) AS firstSeen,
              toString(v.updated_at) AS updatedAt,
              baseUrls, repos
       ORDER BY ${sevOrder('v.severity')}, p.name, v.id
       LIMIT ${SHEET_LIMIT}`,
      { pid })

    // --- totals: computed over the FULL sets, not the truncated sheets -------
    const ecoTotals = await session.run(
      `MATCH (p:Package {project_id: $pid})
       RETURN p.ecosystem AS ecosystem, count(p) AS total,
              count(CASE WHEN p.version IS NULL THEN 1 END) AS unversioned
       ORDER BY total DESC`,
      { pid })

    const verdictTotals = await session.run(
      `MATCH (:Package {project_id: $pid})-[:FLAGGED_AS]->(f:MalPackageFinding {project_id: $pid})
       RETURN f.verdict AS verdict, ${NOT_ANALYSED} AS notAnalysed, count(*) AS c`,
      { pid })

    const sheets = {
      verdicts: verdicts.records.map((r: Neo4jRecord) => ({
        findingId: (r.get('findingId') as string) || '',
        verdict: (r.get('verdict') as string) || 'unknown',
        severity: (r.get('severity') as string) || 'unknown',
        sourceTool: (r.get('sourceTool') as string) ?? null,
        advisoryId: (r.get('advisoryId') as string) ?? null,
        title: (r.get('title') as string) ?? null,
        detail: (r.get('detail') as string) ?? null,
        confidence: (r.get('confidence') as string) ?? null,
        softError: r.get('softError') === true,
        aliases: toStrList(r.get('aliases')),
        firstSeen: (r.get('firstSeen') as string) ?? null,
        lastSeen: (r.get('lastSeen') as string) ?? null,
        purl: (r.get('purl') as string) || '',
        name: (r.get('name') as string) ?? null,
        version: (r.get('version') as string) ?? null,
        ecosystem: (r.get('ecosystem') as string) ?? null,
        harvestSource: (r.get('harvestSource') as string) ?? null,
        sourcePath: (r.get('sourcePath') as string) ?? null,
        baseUrls: toStrList(r.get('baseUrls')),
        repos: toStrList(r.get('repos')),
      })),
      packages: packages.records.map((r: Neo4jRecord) => ({
        purl: (r.get('purl') as string) || '',
        name: (r.get('name') as string) ?? null,
        version: (r.get('version') as string) ?? null,
        ecosystem: (r.get('ecosystem') as string) ?? null,
        harvestSource: (r.get('harvestSource') as string) ?? null,
        sourcePath: (r.get('sourcePath') as string) ?? null,
        firstSeen: (r.get('firstSeen') as string) ?? null,
        lastSeen: (r.get('lastSeen') as string) ?? null,
        baseUrls: toStrList(r.get('baseUrls')),
        repos: toStrList(r.get('repos')),
        maliciousCount: toNum(r.get('maliciousCount')),
        suspiciousCount: toNum(r.get('suspiciousCount')),
        notAnalysedCount: toNum(r.get('notAnalysedCount')),
        advisoryCount: toNum(r.get('advisoryCount')),
        advisorySeverities: toStrList(r.get('advisorySeverities')),
      })),
      advisories: advisories.records.map((r: Neo4jRecord) => ({
        advisoryId: (r.get('advisoryId') as string) || '',
        severity: (r.get('severity') as string) || 'unknown',
        cvss: (r.get('cvss') as string) ?? null,
        title: (r.get('title') as string) ?? null,
        description: (r.get('description') as string) ?? null,
        purl: (r.get('purl') as string) || '',
        name: (r.get('name') as string) ?? null,
        version: (r.get('version') as string) ?? null,
        ecosystem: (r.get('ecosystem') as string) ?? null,
        harvestSource: (r.get('harvestSource') as string) ?? null,
        sourcePath: (r.get('sourcePath') as string) ?? null,
        firstSeen: (r.get('firstSeen') as string) ?? null,
        updatedAt: (r.get('updatedAt') as string) ?? null,
        baseUrls: toStrList(r.get('baseUrls')),
        repos: toStrList(r.get('repos')),
      })),
    }

    const byEcosystem = ecoTotals.records.map((r: Neo4jRecord) => ({
      ecosystem: (r.get('ecosystem') as string) || 'unknown',
      count: toNum(r.get('total')),
      unversioned: toNum(r.get('unversioned')),
    }))

    let malicious = 0
    let suspicious = 0
    let notAnalysed = 0
    for (const r of verdictTotals.records) {
      const c = toNum(r.get('c'))
      if (r.get('notAnalysed') === true) notAnalysed += c
      else if (r.get('verdict') === 'malicious') malicious += c
      else suspicious += c
    }

    const totalPackages = byEcosystem.reduce((s, e) => s + e.count, 0)
    const unversioned = byEcosystem.reduce((s, e) => s + e.unversioned, 0)

    // Sheets are capped; the totals above are not. Without an explicit flag the
    // two silently disagree on a large project and the shorter list reads as
    // the whole truth - the same "absence looks like a clean result" failure the
    // rest of this feature is built to avoid.
    const truncated = {
      verdicts: sheets.verdicts.length >= VERDICT_LIMIT,
      packages: sheets.packages.length >= SHEET_LIMIT,
      advisories: sheets.advisories.length >= SHEET_LIMIT,
    }

    return NextResponse.json({
      sheets,
      meta: {
        totalPackages,
        // Harvested but never actually verdicted: osv-scanner needs a version to
        // match a version-specific advisory, so a versionless package is not
        // "clean", it is UNCHECKED. Surfaced as a first-class number so an empty
        // verdict list is never read as a clean result.
        unversioned,
        malicious,
        suspicious,
        notAnalysed,
        advisories: sheets.advisories.length,
        truncated,
        byEcosystem,
        verdicts: sheets.verdicts.length,
        packages: sheets.packages.length,
      },
    })
  } catch (error) {
    console.error('Red-zone supplyChainSca error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' }, { status: 500 })
  } finally {
    await session.close()
  }
}
