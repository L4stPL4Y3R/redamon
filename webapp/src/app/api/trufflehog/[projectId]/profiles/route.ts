import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { Prisma } from '@prisma/client'
import {
  getTrufflehogSource,
  resolveMissingCredentials,
  validateTrufflehogConfig,
  TRUFFLEHOG_CREDENTIAL_FIELDS,
} from '@/lib/trufflehogSources'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

const CREDENTIAL_SELECT = Object.fromEntries(
  TRUFFLEHOG_CREDENTIAL_FIELDS.map(f => [f, true]),
) as Record<string, true>

/**
 * List the project's configured sources.
 *
 * Each row carries `missingCredentials` so the card can disable Start and say
 * which key to set, without the client ever seeing a credential VALUE — only
 * the names of the ones that are empty.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { userId: true },
  })
  if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 })

  const [profiles, settings] = await Promise.all([
    prisma.trufflehogScanProfile.findMany({
      where: { projectId },
      orderBy: { createdAt: 'asc' },
    }),
    prisma.userSettings.findUnique({
      where: { userId: project.userId },
      select: CREDENTIAL_SELECT,
    }),
  ])

  return NextResponse.json({
    profiles: profiles.map(p => {
      const config = (p.config ?? {}) as Record<string, unknown>
      return {
        ...p,
        validationErrors: validateTrufflehogConfig(p.source, config),
        missingCredentials: resolveMissingCredentials(
          p.source, config, settings as Record<string, unknown> | null,
        ).map(c => ({ settingsKey: c.settingsKey, label: c.label })),
      }
    }),
  })
}

/**
 * Create a profile for a source.
 *
 * The unique (projectId, source) constraint is what makes "one run per source"
 * a database invariant rather than a convention — the same rule the runtime run
 * key enforces.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const body = await request.json().catch(() => ({}))
    const src = getTrufflehogSource(String(body.source ?? ''))
    if (!src) {
      return NextResponse.json(
        { error: `Unknown TruffleHog source: ${body.source}` },
        { status: 400 },
      )
    }

    const config = (body.config ?? {}) as Record<string, unknown>
    const rejected = rejectSecretFields(src.id, config)
    if (rejected) return NextResponse.json({ error: rejected }, { status: 400 })

    const existing = await prisma.trufflehogScanProfile.findUnique({
      where: { projectId_source: { projectId, source: src.id } },
      select: { id: true },
    })
    if (existing) {
      return NextResponse.json(
        { error: `A ${src.label} profile already exists for this project` },
        { status: 409 },
      )
    }

    const profile = await prisma.trufflehogScanProfile.create({
      data: {
        projectId,
        source: src.id,
        label: String(body.label ?? '').slice(0, 200),
        config: config as Prisma.InputJsonValue,
      },
    })
    return NextResponse.json({ profile }, { status: 201 })
  } catch (error) {
    console.error('Error creating TruffleHog profile:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}

/**
 * A profile row is exported verbatim into project.json, so a token stored in
 * `config` would leave with the export zip. Refuse the write rather than
 * silently stripping it, so a client sending one finds out.
 */
export function rejectSecretFields(sourceId: string, config: Record<string, unknown>): string | null {
  const src = getTrufflehogSource(sourceId)
  const known = new Set((src?.fields ?? []).map(f => f.key))
  for (const key of Object.keys(config)) {
    if (!known.has(key)) {
      return `'${key}' is not a field of the ${src?.label ?? sourceId} source`
    }
    if (/(?:token|password|secret|apikey|api_key)$/i.test(key)) {
      return `'${key}' looks like a credential. TruffleHog credentials live in `
        + 'Global Settings > API Keys, never in a scan profile.'
    }
  }
  return null
}
