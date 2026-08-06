'use client'

import { useState } from 'react'
import { ChevronDown, PackageSearch, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SupplyChainReconSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

/**
 * L2 - Supply Chain Recon: the recon-pipeline module (GROUP 5.5, after JS Recon).
 * The standalone SBOM/lockfile scan (L1) lives in SupplyChainSection under the
 * "Other Scans" tab; this section is only the pipeline tool.
 */
export function SupplyChainReconSection({ data, updateField, onRun }: SupplyChainReconSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const d = data as unknown as {
    supplyChainReconEnabled?: boolean
    supplyChainReconEcosystems?: string
    supplyChainReconDeepAnalysisEnabled?: boolean
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <PackageSearch size={16} />
          Supply Chain Recon
          <NodeInfoTooltip section="SupplyChainRecon" />
          <WikiInfoButton target="SupplyChain" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && d.supplyChainReconEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 8px', borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
              }}
              title="Run Supply Chain Recon"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Works out which packages the target actually ships, without a manifest. It mines package names from
            source maps, module imports, and the detected technology stack, then checks them against a local copy
            of the OSV vulnerability database. Runs after JS Recon and re-uses the JavaScript it already
            downloaded, so it sends no extra traffic to the target, and the verdict is fully offline.
          </p>

          <div className={styles.fieldGroup} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Toggle
              checked={!!d.supplyChainReconEnabled}
              onChange={(v) => updateField('supplyChainReconEnabled' as keyof FormData, v as never)}
              aria-label="Enable Supply Chain Recon"
            />
            <label className={styles.fieldLabel} style={{ margin: 0 }}>Enable Supply Chain Recon</label>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Ecosystems</label>
            <input
              type="text"
              className={styles.input}
              value={d.supplyChainReconEcosystems ?? 'npm'}
              onChange={(e) => updateField('supplyChainReconEcosystems' as keyof FormData, e.target.value as never)}
              placeholder="npm"
            />
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Comma-separated ecosystems to report. Each must be present in the offline database, populated with{' '}
              <code>./redamon.sh supply-chain-sync npm</code>. Valid: npm, PyPI, Go, Maven, crates.io, Packagist, RubyGems, NuGet.
            </p>
          </div>

          <div className={styles.fieldGroup}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Toggle
                checked={!!d.supplyChainReconDeepAnalysisEnabled}
                onChange={(v) => updateField('supplyChainReconDeepAnalysisEnabled' as keyof FormData, v as never)}
                aria-label="Deep behavioural analysis"
              />
              <label className={styles.fieldLabel} style={{ margin: 0 }}>Deep behavioural analysis (GuardDog)</label>
            </div>
            <p style={{ fontSize: '12px', color: '#f59e0b', marginTop: '4px' }}>
              Downloads the package archive of a flagged dependency and inspects it inside a hardened,
              network-isolated sandbox. This reaches out to public package registries, so it stays off unless you
              specifically need behavioural evidence.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
