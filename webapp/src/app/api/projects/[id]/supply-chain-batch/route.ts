/**
 * Scan Queue Phase 6 - create a supply-chain org batch. Project-scoped, so
 * guardProject runs FIRST. Enumerates the GitHub org's repos and, in ONE
 * transaction, writes the batch, its items, and one supply_chain_repo JobQueue row
 * per repo (priority -10, below manual and scheduled). The dispatcher runs them.
 *
 * The GitHub token is resolved server-side from UserSettings (never from the
 * request body) and never stored on a row or returned. Every owner/repo/ref is
 * validated before it is persisted (and again in the container before git clone).
 */
import { NextRequest, NextResponse } from 'next/server'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { guardProject } from '@/lib/access'
import { getEffectiveUser } from '@/lib/session'
import { settingsFingerprint, envelopeForKind } from '@/lib/jobQueue'
import { listOwnerRepos, isValidGitRef, isValidOwner, GithubEnumError } from '@/lib/github/orgRepos'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id: projectId } = await params
    const denied = await guardProject(projectId)
    if (denied) return denied

    const eff = await getEffectiveUser()
    if (!eff?.userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

    const project = await prisma.project.findUnique({ where: { id: projectId } })
    if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 })

    const body = await request.json().catch(() => ({}))
    const org = (typeof body?.org === 'string' && body.org.trim()) ? body.org.trim() : project.supplyChainOrgName
    if (!org || !isValidOwner(org)) {
      return NextResponse.json({ error: 'A valid GitHub organization or user is required.' }, { status: 400 })
    }

    // Token resolved server-side from the operator's settings; optional (public
    // repos enumerate without it). NEVER read from the request body.
    const settings = await prisma.userSettings.findUnique({
      where: { userId: eff.userId }, select: { githubAccessToken: true },
    }).catch(() => null)
    const token = settings?.githubAccessToken || undefined

    const orgRef = project.supplyChainOrgRef || ''
    if (orgRef && !isValidGitRef(orgRef)) {
      return NextResponse.json({ error: 'Configured org ref is not a valid git ref.' }, { status: 400 })
    }

    let repos
    try {
      repos = await listOwnerRepos(org, {
        token,
        includeForks: project.supplyChainOrgIncludeForks,
        includeArchived: project.supplyChainOrgIncludeArchived,
        maxRepos: Math.max(1, project.supplyChainOrgMaxRepos || 50),
      })
    } catch (e) {
      const status = e instanceof GithubEnumError && e.status ? e.status : 502
      return NextResponse.json({ error: e instanceof Error ? e.message : 'GitHub enumeration failed' }, { status })
    }

    if (repos.length === 0) {
      return NextResponse.json({ error: `No scannable repositories found for '${org}'.` }, { status: 400 })
    }

    const settingsHash = settingsFingerprint('supply_chain_repo', project as unknown as Record<string, unknown>)
    const envelopeBytes = BigInt(envelopeForKind('supply_chain_repo'))
    const deepAnalysis = project.supplyChainOrgDeepAnalysisEnabled
    const scope = project.supplyChainRepoScope || ''

    const result = await prisma.$transaction(async tx => {
      const batch = await tx.supplyChainBatch.create({
        data: { projectId, userId: eff.userId, org, status: 'running', totalItems: repos.length },
        select: { id: true },
      })

      for (const r of repos) {
        const ref = orgRef || r.defaultBranch || ''
        const safeRef = isValidGitRef(ref) ? ref : ''
        const payload = {
          repo_url: r.url,
          repo_full_name: r.fullName,
          ref: safeRef,
          scope,
          deep_analysis: deepAnalysis,
        }
        const job = await tx.jobQueue.create({
          data: {
            projectId,
            userId: eff.userId,
            kind: 'supply_chain_repo',
            payload: payload as Prisma.InputJsonValue,
            settingsHash,
            envelopeBytes,
            priority: -10, // batch item: below manual (10) and scheduled (0)
            batchId: batch.id,
            status: 'queued',
          },
          select: { id: true },
        })
        await tx.supplyChainBatchItem.create({
          data: {
            batchId: batch.id,
            repoFullName: r.fullName,
            repoUrl: r.url,
            ref: safeRef,
            status: 'queued',
            jobId: job.id,
          },
        })
      }

      return batch
    }, {
      // Up to maxRepos (default 50) x 2 writes; the 5s default is too tight under
      // load. Cap the enumeration at maxRepos keeps this bounded.
      timeout: 30_000,
      maxWait: 10_000,
    })

    return NextResponse.json({ ok: true, batchId: result.id, totalItems: repos.length }, { status: 201 })
  } catch (error) {
    console.error('[supplyChainBatch] create failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
