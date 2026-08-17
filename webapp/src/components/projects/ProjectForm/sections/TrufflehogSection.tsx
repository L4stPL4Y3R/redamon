'use client'

import { useCallback, useEffect, useState } from 'react'
import { ChevronDown, Plus, Search, Trash2, AlertTriangle } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import Link from 'next/link'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import {
  TRUFFLEHOG_SOURCES,
  TRUFFLEHOG_SOURCE_IDS,
  type TrufflehogField,
  validateTrufflehogConfig,
} from '@/lib/trufflehogSources'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TrufflehogProfile {
  id: string
  source: string
  label: string
  config: Record<string, unknown>
  validationErrors?: string[]
  missingCredentials?: { settingsKey: string; label: string }[]
}

interface TrufflehogSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  /** Profiles are per-project rows, so they can only be managed once the project
   *  exists. In create mode the section shows the shared options only. */
  projectId?: string | null
  mode?: 'create' | 'edit'
}

const RESULT_TYPES = [
  { value: 'verified', label: 'Verified (confirmed live)' },
  { value: 'unverified', label: 'Unverified (detected, not confirmed)' },
  { value: 'unknown', label: 'Unknown (the verify call failed)' },
  { value: 'filtered_unverified', label: 'Filtered unverified' },
]

const get = (data: FormData, key: string) => (data as unknown as Record<string, unknown>)[key]
const setField = (
  updateField: TrufflehogSectionProps['updateField'],
  key: string,
  value: unknown,
) => updateField(key as keyof FormData, value as FormData[keyof FormData])

export function TrufflehogSection({ data, updateField, projectId, mode = 'edit' }: TrufflehogSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [profiles, setProfiles] = useState<TrufflehogProfile[]>([])
  const [addingSource, setAddingSource] = useState('')
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const canManageProfiles = mode === 'edit' && Boolean(projectId)

  const loadProfiles = useCallback(async () => {
    if (!canManageProfiles) return
    try {
      const res = await fetch(`/api/trufflehog/${projectId}/profiles`)
      if (!res.ok) return
      const body = await res.json()
      setProfiles(body.profiles ?? [])
    } catch {
      // A failed list must not break the whole project form.
    }
  }, [canManageProfiles, projectId])

  useEffect(() => { void loadProfiles() }, [loadProfiles])

  // Verification is the headline control: it makes RedAmon send found
  // credentials to their owning services to test whether they are live. Default
  // ON (it is TruffleHog's whole value), but the badge has to tell the truth.
  const skipVerification = (get(data, 'trufflehogNoVerification') as boolean) ?? false
  const verifies = !skipVerification

  const resultTypes = String((get(data, 'trufflehogResultTypes') as string) ?? 'verified,unverified,unknown')
    .split(',').map(s => s.trim()).filter(Boolean)

  const toggleResultType = (value: string) => {
    const next = resultTypes.includes(value)
      ? resultTypes.filter(v => v !== value)
      : [...resultTypes, value]
    setField(updateField, 'trufflehogResultTypes', next.join(','))
  }

  const addProfile = async () => {
    if (!addingSource || !projectId) return
    setError('')
    const res = await fetch(`/api/trufflehog/${projectId}/profiles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: addingSource, config: {} }),
    })
    const body = await res.json().catch(() => ({}))
    if (!res.ok) { setError(body.error ?? 'Could not add the source'); return }
    setAddingSource('')
    setExpanded(body.profile?.id ?? null)
    await loadProfiles()
  }

  const saveProfile = async (profile: TrufflehogProfile, config: Record<string, unknown>) => {
    if (!projectId) return
    setError('')
    setProfiles(prev => prev.map(p => (p.id === profile.id ? { ...p, config } : p)))
    const res = await fetch(`/api/trufflehog/${projectId}/profiles/${profile.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      setError(body.error ?? 'Could not save the source')
    }
  }

  const deleteProfile = async (profile: TrufflehogProfile) => {
    if (!projectId) return
    await fetch(`/api/trufflehog/${projectId}/profiles/${profile.id}`, { method: 'DELETE' })
    await loadProfiles()
  }

  const unconfigured = TRUFFLEHOG_SOURCE_IDS.filter(id => !profiles.some(p => p.source === id))

  return (
    // id: scroll target for the Other Scans card's settings link. Keep it in
    // sync with PROJECT_SECTION_ANCHORS in lib/projectSettingsLinks.ts.
    <div className={styles.section} id="trufflehog-scanner">
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Search size={16} />
          TruffleHog Secret Scanner
          <WikiInfoButton target="Trufflehog" />
          {/* Dynamic, not a fixed "Passive": with verification on, the scanner
              authenticates to third-party services with credentials it found. */}
          <span className={verifies ? styles.badgeActive : styles.badgePassive}>
            {verifies ? 'Active' : 'Passive'}
          </span>
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Deep secret scanning with 700+ detectors across 14 sources — git hosts, container
            registries, Hugging Face, object storage, CI systems and more. Each configured source
            runs as its own scan, and several can run at the same time.
          </p>

          {/* ---- The verification switch: always visible, never gated behind a
                  configured target. Hiding it is why the control could not be
                  found at all. ---- */}
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Verify secrets against live APIs</span>
              <p className={styles.toggleDescription}>
                When on, RedAmon sends found credentials to their owning services to test whether
                they are live. This is the highest-value result in an authorised engagement, but it
                is an ACTIVE behaviour. Use the detector exclude list below to skip services you do
                not want contacted.
              </p>
            </div>
            <Toggle
              checked={verifies}
              onChange={(checked) => setField(updateField, 'trufflehogNoVerification', !checked)}
            />
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Result types</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
              {RESULT_TYPES.map(rt => (
                <label
                  key={rt.value}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px',
                    opacity: verifies ? 1 : 0.5,
                  }}
                >
                  <input
                    type="checkbox"
                    checked={resultTypes.includes(rt.value)}
                    disabled={!verifies}
                    onChange={() => toggleResultType(rt.value)}
                  />
                  {rt.label}
                </label>
              ))}
            </div>
            <span className={styles.fieldHint}>
              {verifies
                ? 'Which statuses to report. Orthogonal to the switch above.'
                : 'Disabled while verification is off — nothing is checked, so every finding is unverified.'}
            </span>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Concurrency</label>
            <input
              type="number"
              className="textInput"
              value={(get(data, 'trufflehogConcurrency') as number) ?? 8}
              onChange={(e) => setField(updateField, 'trufflehogConcurrency', parseInt(e.target.value) || 8)}
              min={1}
              max={32}
            />
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Include detectors</label>
            <input
              type="text"
              className="textInput"
              value={(get(data, 'trufflehogIncludeDetectors') as string) ?? ''}
              onChange={(e) => setField(updateField, 'trufflehogIncludeDetectors', e.target.value)}
              placeholder="AWS,GitHub,Slack"
            />
            <span className={styles.fieldHint}>Comma-separated. Leave empty for all.</span>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Exclude detectors</label>
            <input
              type="text"
              className="textInput"
              value={(get(data, 'trufflehogExcludeDetectors') as string) ?? ''}
              onChange={(e) => setField(updateField, 'trufflehogExcludeDetectors', e.target.value)}
              placeholder="DetectorName1,DetectorName2"
            />
            <span className={styles.fieldHint}>
              Takes precedence over the include list. This is the blast-radius control for
              verification: an excluded detector is never contacted.
            </span>
          </div>

          {/* ---- Per-source profiles ---- */}
          <h3 className={styles.subSectionTitle ?? styles.fieldLabel}>Sources</h3>

          {!canManageProfiles ? (
            <p className={styles.sectionRequirement}>
              Save the project first, then add the sources to scan here.
            </p>
          ) : (
            <>
              {error && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 14px',
                  background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '8px', marginBottom: '12px',
                }}>
                  <AlertTriangle size={16} style={{ color: '#ef4444', flexShrink: 0 }} />
                  <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{error}</span>
                </div>
              )}

              {profiles.length === 0 && (
                <p className={styles.fieldHint}>
                  No sources configured yet. Add one below to make it startable from Other Scans.
                </p>
              )}

              {profiles.map(profile => (
                <ProfileEditor
                  key={profile.id}
                  profile={profile}
                  expanded={expanded === profile.id}
                  onToggle={() => setExpanded(expanded === profile.id ? null : profile.id)}
                  onSave={config => saveProfile(profile, config)}
                  onDelete={() => deleteProfile(profile)}
                />
              ))}

              {unconfigured.length > 0 && (
                <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
                  <select
                    className="textInput"
                    value={addingSource}
                    onChange={(e) => setAddingSource(e.target.value)}
                    style={{ flex: 1 }}
                  >
                    <option value="">Add a source…</option>
                    {unconfigured.map(id => (
                      <option key={id} value={id}>{TRUFFLEHOG_SOURCES[id].label}</option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="btnSecondary"
                    onClick={addProfile}
                    disabled={!addingSource}
                  >
                    <Plus size={14} /> Add
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}

function ProfileEditor({
  profile, expanded, onToggle, onSave, onDelete,
}: {
  profile: TrufflehogProfile
  expanded: boolean
  onToggle: () => void
  onSave: (config: Record<string, unknown>) => void
  onDelete: () => void
}) {
  const src = TRUFFLEHOG_SOURCES[profile.source]
  const [config, setConfig] = useState<Record<string, unknown>>(profile.config ?? {})

  useEffect(() => { setConfig(profile.config ?? {}) }, [profile.config])

  if (!src) return null

  const errors = validateTrufflehogConfig(profile.source, config)
  const missing = profile.missingCredentials ?? []
  const sweepMode = String(config.mode ?? 'assets') === 'sweep'

  const update = (key: string, value: unknown) => {
    const next = { ...config, [key]: value }
    setConfig(next)
    onSave(next)
  }

  const isDisabled = (field: TrufflehogField) => {
    if (!field.requires) return false
    // 'sweep' names the Hugging Face mode; anything else names another field
    // that must be non-empty (the org-only GitHub options).
    if (field.requires === 'sweep') return !sweepMode
    const other = config[field.requires]
    return !(Array.isArray(other) ? other.length : String(other ?? '').length)
  }

  return (
    <div style={{
      border: '1px solid var(--border-primary)', borderRadius: '8px',
      padding: '10px 14px', marginBottom: '8px',
    }}>
      <div
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
        onClick={onToggle}
      >
        <div>
          <strong style={{ fontSize: '14px' }}>{src.label}</strong>
          {errors.length > 0 && (
            <span style={{ marginLeft: '8px', fontSize: '12px', color: '#f59e0b' }}>
              needs configuration
            </span>
          )}
          {missing.length > 0 && (
            <span style={{ marginLeft: '8px', fontSize: '12px', color: '#ef4444' }}>
              missing {missing.map(m => m.label).join(', ')}
            </span>
          )}
        </div>
        <button
          type="button"
          className="btnIcon"
          onClick={(e) => { e.stopPropagation(); onDelete() }}
          aria-label={`Remove the ${src.label} source`}
        >
          <Trash2 size={14} />
        </button>
      </div>

      {expanded && (
        <div style={{ marginTop: '10px' }}>
          <p className={styles.fieldHint}>{src.description}</p>

          {missing.length > 0 && (
            <p className={styles.sectionRequirement}>
              {src.label} requires {missing.map(m => m.label).join(', ')}. Set it in{' '}
              <Link href={`${SETTINGS_KEYS_HREF}#trufflehog-keys`} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                Global Settings &gt; API Keys &gt; TruffleHog
              </Link>
              . Until then this source cannot start.
            </p>
          )}

          {src.fields.map(field => (
            <FieldInput
              key={field.key}
              field={field}
              value={config[field.key]}
              disabled={isDisabled(field)}
              onChange={value => update(field.key, value)}
            />
          ))}

          {errors.map(e => (
            <p key={e} className={styles.fieldHint} style={{ color: '#f59e0b' }}>{e}</p>
          ))}
        </div>
      )}
    </div>
  )
}

/** Renders one registry field. The control follows `field.type`, which is the
 *  same value the Python side uses to build argv — so what the operator types
 *  and what TruffleHog receives cannot diverge in shape. */
function FieldInput({
  field, value, disabled, onChange,
}: {
  field: TrufflehogField
  value: unknown
  disabled: boolean
  onChange: (value: unknown) => void
}) {
  const asText = String(value ?? '')
  const asCsv = Array.isArray(value) ? value.join(', ') : asText

  if (field.type === 'toggle') {
    return (
      <div className={styles.toggleRow} style={{ opacity: disabled ? 0.5 : 1 }}>
        <div>
          <span className={styles.toggleLabel}>{field.label}</span>
          {field.hint && <p className={styles.toggleDescription}>{field.hint}</p>}
        </div>
        <Toggle checked={Boolean(value)} onChange={onChange} disabled={disabled} />
      </div>
    )
  }

  return (
    <div className={styles.fieldGroup} style={{ opacity: disabled ? 0.5 : 1 }}>
      <label className={styles.fieldLabel}>
        {field.label}{field.required ? ' *' : ''}
      </label>

      {field.type === 'select' ? (
        <select
          className="textInput"
          value={asText}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">Select…</option>
          {(field.options ?? []).map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      ) : field.type === 'pathfile' || field.type === 'textarea' ? (
        <textarea
          className="textInput"
          rows={3}
          value={asText}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : field.type === 'number' ? (
        <input
          type="number"
          className="textInput"
          value={asText}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value === '' ? '' : Number(e.target.value))}
        />
      ) : (
        <input
          type="text"
          className="textInput"
          value={asCsv}
          disabled={disabled}
          // multi/csv fields are typed comma-separated and stored as a list, so
          // the registry's `multi` type reaches Python as repeated flags.
          onChange={(e) => onChange(
            field.type === 'multi'
              ? e.target.value.split(',').map(s => s.trim()).filter(Boolean)
              : e.target.value,
          )}
        />
      )}

      {field.hint && <span className={styles.fieldHint}>{field.hint}</span>}
    </div>
  )
}
