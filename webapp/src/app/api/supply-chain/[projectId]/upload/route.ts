import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { mkdir, writeFile, readdir, stat, unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

// Shared with the supply-chain scan container (named volume supply_chain_uploads).
const SUPPLY_CHAIN_UPLOAD_PATH = process.env.SUPPLY_CHAIN_UPLOAD_PATH || '/data/supply-chain-uploads'
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10 MB
// SBOMs + committed lockfiles only. NEVER an archive/script (S1/S7).
const ALLOWED_EXTENSIONS = ['.json', '.xml', '.txt', '.lock', '.toml', '.mod', '.sum', '.yaml']

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]+$/

function sanitizeFilename(name: string): string {
  return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_')
}

function isAllowedExtension(filename: string): boolean {
  return ALLOWED_EXTENSIONS.includes(path.extname(filename).toLowerCase())
}

interface RouteParams {
  params: Promise<{ projectId: string }>
}

// GET -- list uploaded SBOM/lockfiles for this project.
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }
    const projectDir = path.join(SUPPLY_CHAIN_UPLOAD_PATH, projectId)
    if (!existsSync(projectDir)) return NextResponse.json({ files: [] })

    const files = []
    for (const entry of await readdir(projectDir)) {
      try {
        const s = await stat(path.join(projectDir, entry))
        if (s.isFile()) files.push({ name: entry, size: s.size, uploaded_at: s.mtime.toISOString() })
      } catch { /* skip */ }
    }
    return NextResponse.json({ files })
  } catch (error) {
    console.error('Error listing Supply-Chain uploads:', error)
    return NextResponse.json({ error: 'Failed to list files' }, { status: 500 })
  }
}

// POST -- upload one SBOM/lockfile; becomes the scan input (supplyChainSbomFile).
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    const formData = await request.formData()
    const file = formData.get('file') as File | null
    if (!file) return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json({ error: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024}MB` }, { status: 400 })
    }

    const filename = sanitizeFilename(file.name)
    if (!isAllowedExtension(filename)) {
      return NextResponse.json({ error: `Invalid file type. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}` }, { status: 400 })
    }

    const projectDir = path.join(SUPPLY_CHAIN_UPLOAD_PATH, projectId)
    await mkdir(projectDir, { recursive: true })
    const buffer = Buffer.from(await file.arrayBuffer())
    await writeFile(path.join(projectDir, filename), buffer)

    // The latest upload becomes the active scan input.
    try {
      await prisma.project.update({ where: { id: projectId }, data: { supplyChainSbomFile: filename } })
    } catch { /* project may not exist yet during creation; DB update happens on save */ }

    return NextResponse.json({ success: true, filename })
  } catch (error) {
    console.error('Error uploading SBOM:', error)
    return NextResponse.json({ error: 'Failed to upload file' }, { status: 500 })
  }
}

// DELETE -- remove an uploaded file (and clear it as the active input).
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied
    const { searchParams } = new URL(request.url)
    const filename = sanitizeFilename(searchParams.get('filename') || '')
    if (!filename) return NextResponse.json({ error: 'No filename' }, { status: 400 })

    const filePath = path.join(SUPPLY_CHAIN_UPLOAD_PATH, projectId, filename)
    if (existsSync(filePath)) await unlink(filePath)
    try {
      const current = await prisma.project.findUnique({ where: { id: projectId }, select: { supplyChainSbomFile: true } })
      if (current?.supplyChainSbomFile === filename) {
        await prisma.project.update({ where: { id: projectId }, data: { supplyChainSbomFile: '' } })
      }
    } catch { /* skip */ }
    return NextResponse.json({ success: true })
  } catch (error) {
    return NextResponse.json({ error: 'Failed to delete file' }, { status: 500 })
  }
}
