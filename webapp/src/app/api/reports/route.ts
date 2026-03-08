import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

/** GET /api/reports — List all reports across ALL projects */
export async function GET() {
  try {
    const reports = await prisma.report.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        projectId: true,
        title: true,
        filename: true,
        fileSize: true,
        format: true,
        metrics: true,
        hasNarratives: true,
        createdAt: true,
        project: {
          select: {
            id: true,
            name: true,
            targetDomain: true,
          },
        },
      },
    })
    return NextResponse.json(reports)
  } catch (error) {
    console.error('List all reports failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to list reports' },
      { status: 500 }
    )
  }
}
