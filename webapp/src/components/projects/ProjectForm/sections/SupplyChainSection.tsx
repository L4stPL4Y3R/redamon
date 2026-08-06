'use client'

import { useState, useEffect, useCallback } from 'react'
import { ChevronDown, PackageSearch, Upload, Trash2 } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SupplyChainSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
}

interface UploadedFile { name: string; size: number; uploaded_at: string }

export function SupplyChainSection({ data, updateField, projectId }: SupplyChainSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [files, setFiles] = useState<UploadedFile[]>([])
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const d = data as unknown as {
    supplyChainEnabled?: boolean
    supplyChainSbomFile?: string
    supplyChainDeepAnalysisEnabled?: boolean
  }

  const refresh = useCallback(async () => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/supply-chain/${projectId}/upload`)
      if (res.ok) setFiles((await res.json()).files || [])
    } catch { /* ignore */ }
  }, [projectId])

  useEffect(() => { void refresh() }, [refresh])

  const onUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !projectId) return
    setUploading(true); setError(null)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await fetch(`/api/supply-chain/${projectId}/upload`, { method: 'POST', body: fd })
      const j = await res.json()
      if (!res.ok) { setError(j.error || 'Upload failed') }
      else { updateField('supplyChainSbomFile' as keyof FormData, j.filename as never); await refresh() }
    } catch { setError('Upload failed') }
    finally { setUploading(false); e.target.value = '' }
  }

  const onDelete = async (name: string) => {
    if (!projectId) return
    try {
      await fetch(`/api/supply-chain/${projectId}/upload?filename=${encodeURIComponent(name)}`, { method: 'DELETE' })
      if (d.supplyChainSbomFile === name) updateField('supplyChainSbomFile' as keyof FormData, '' as never)
      await refresh()
    } catch { /* ignore */ }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <PackageSearch size={16} />
          Supply Chain Scan (SBOM / lockfile)
          <WikiInfoButton target="SupplyChain" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Detect known-malicious (MAL) and known-vulnerable packages, fully offline against the local OSV database.
Audits an uploaded SBOM or lockfile. The live-target harvest is a separate module in the JS Recon stage of the recon pipeline.
          </p>

          {/* L1: standalone SBOM scan */}
          <div className={styles.fieldGroup} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Toggle
              checked={!!d.supplyChainEnabled}
              onChange={(v) => updateField('supplyChainEnabled' as keyof FormData, v as never)}
              aria-label="Supply-Chain Scan"
            />
            <label className={styles.fieldLabel} style={{ margin: 0 }}>Enable Supply-Chain Scan</label>
          </div>

          {projectId && (
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>SBOM / lockfile</label>
              <label className={styles.uploadButton} style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <Upload size={14} />
                <span>{uploading ? 'Uploading...' : 'Upload SBOM / lockfile'}</span>
                <input type="file" accept=".json,.xml,.txt,.lock,.toml,.mod,.sum,.yaml,.yml" style={{ display: 'none' }} onChange={onUpload} disabled={uploading} />
              </label>
              {error && <p style={{ color: '#ef4444', fontSize: '12px', marginTop: '6px' }}>{error}</p>}
              {files.length > 0 && (
                <ul style={{ listStyle: 'none', padding: 0, marginTop: '8px' }}>
                  {files.map((f) => (
                    <li key={f.name} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', padding: '4px 0' }}>
                      <span style={{ fontWeight: d.supplyChainSbomFile === f.name ? 600 : 400 }}>
                        {f.name}{d.supplyChainSbomFile === f.name ? ' (active)' : ''}
                      </span>
                      <button type="button" onClick={() => onDelete(f.name)} title="Delete"
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }}>
                        <Trash2 size={13} />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                Accepted: package-lock.json, requirements.txt, go.mod, Cargo.lock, composer.lock, Gemfile.lock, pom.xml, or a CycloneDX SBOM (*.cdx.json). Static offline parse only, never installed.
              </p>
            </div>
          )}

        </div>
      )}
    </div>
  )
}
