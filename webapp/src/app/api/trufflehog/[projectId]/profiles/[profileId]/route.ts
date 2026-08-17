import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { Prisma } from '@prisma/client'
import { getTrufflehogSource } from '@/lib/trufflehogSources'
import { rejectSecretFields } from '../route'

interface RouteParams {
  params: Promise<{ projectId: string; profileId: string }>
}

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, profileId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // Scoped to the project, not just the id: a profile id from another project
    // must 404, not update.
    const profile = await prisma.trufflehogScanProfile.findFirst({
      where: { id: profileId, projectId },
      select: { id: true, source: true },
    })
    if (!profile) return NextResponse.json({ error: 'Profile not found' }, { status: 404 })

    const body = await request.json().catch(() => ({}))
    const data: { label?: string; config?: Prisma.InputJsonValue } = {}

    if (typeof body.label === 'string') data.label = body.label.slice(0, 200)
    if (body.config && typeof body.config === 'object') {
      const config = body.config as Record<string, unknown>
      const rejected = rejectSecretFields(profile.source, config)
      if (rejected) return NextResponse.json({ error: rejected }, { status: 400 })
      data.config = config as Prisma.InputJsonValue
    }

    // The source is the run key and the unique-constraint half; changing it
    // would silently re-point history, findings and the queued job's identity.
    if (body.source && getTrufflehogSource(String(body.source))?.id !== profile.source) {
      return NextResponse.json(
        { error: 'A profile\'s source cannot be changed. Delete it and add the other source.' },
        { status: 400 },
      )
    }

    const updated = await prisma.trufflehogScanProfile.update({
      where: { id: profileId },
      data,
    })
    return NextResponse.json({ profile: updated })
  } catch (error) {
    console.error('Error updating TruffleHog profile:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, profileId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const profile = await prisma.trufflehogScanProfile.findFirst({
      where: { id: profileId, projectId },
      select: { id: true },
    })
    if (!profile) return NextResponse.json({ error: 'Profile not found' }, { status: 404 })

    await prisma.trufflehogScanProfile.delete({ where: { id: profileId } })
    return NextResponse.json({ ok: true })
  } catch (error) {
    console.error('Error deleting TruffleHog profile:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
