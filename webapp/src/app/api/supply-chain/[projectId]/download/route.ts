import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { readFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

// Path to the L1 Supply-Chain scan output directory (mounted volume or local path).
// The CLEAN writer saves supply_chain_<projectId>.json here (see
// scanners/supply_chain_scan/main.py:163, SUPPLY_CHAIN_OUTPUT_DIR).
const SUPPLY_CHAIN_OUTPUT_PATH = process.env.SUPPLY_CHAIN_OUTPUT_PATH || '/data/supply-chain-output'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, name: true }
    })

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    const jsonFileName = `supply_chain_${projectId}.json`
    const jsonFilePath = path.join(SUPPLY_CHAIN_OUTPUT_PATH, jsonFileName)

    if (!existsSync(jsonFilePath)) {
      return NextResponse.json(
        { error: 'Supply-chain data not found. Run a Supply Chain scan first.' },
        { status: 404 }
      )
    }

    const fileContent = await readFile(jsonFilePath, 'utf-8')

    return new NextResponse(fileContent, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="${jsonFileName}"`,
        'Cache-Control': 'no-cache',
      },
    })

  } catch (error) {
    console.error('Error downloading supply-chain data:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}

// Also support HEAD request to check if data exists
export async function HEAD(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true }
    })

    if (!project) {
      return new NextResponse(null, { status: 404 })
    }

    const jsonFilePath = path.join(SUPPLY_CHAIN_OUTPUT_PATH, `supply_chain_${projectId}.json`)

    if (!existsSync(jsonFilePath)) {
      return new NextResponse(null, { status: 404 })
    }

    return new NextResponse(null, { status: 200 })

  } catch {
    return new NextResponse(null, { status: 500 })
  }
}
