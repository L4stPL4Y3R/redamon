'use client'

import { useState } from 'react'
import { ChevronDown, Github } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'
import Link from 'next/link'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import { CredentialShortcut } from '@/components/settings/CredentialShortcut'
import { useCredentialKeys } from '@/hooks/useCredentialKeys'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface GithubSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  hasGithubToken?: boolean
}

export function GithubSection({ data, updateField, hasGithubToken = false }: GithubSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const keys = useCredentialKeys()

  // The prop is resolved server-side when the form loads, so it stays false
  // after an inline save; OR-ing in the live value unlocks the fields below
  // straight away instead of needing a reload.
  const tokenSet = hasGithubToken || keys.isSet('githubAccessToken')

  return (
    // id: scroll target for the Other Scans card's settings link. Keep it in
    // sync with PROJECT_SECTION_ANCHORS in lib/projectSettingsLinks.ts.
    <div className={styles.section} id="github-secret-hunting">
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Github size={16} />
          GitHub Secret Hunting
          <NodeInfoTooltip section="Github" />
          <WikiInfoButton target="Github" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Search GitHub repositories for exposed secrets, API keys, and credentials related to your target domain. Identifies leaked sensitive data that could enable unauthorized access to systems and services.
          </p>

          <p className={styles.sectionRequirement}>
            Requires a GitHub Access Token in{' '}
            <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
              Global Settings
            </Link>
            . Mandatory even for public repositories: without one GitHub allows 60 requests
            per hour, which this scan exhausts immediately. Private repositories additionally
            need a token with repo scope, and only an organization you belong to exposes them
            (a personal account is read through its public profile).
          </p>

          {/* Set the token here rather than losing a half-filled form to a trip
              to /settings. It is a user-level key shared by every project, which
              is what the shortcut's own badge says. */}
          <div style={{ marginBottom: '12px' }}>
            <CredentialShortcut settingsKey="githubAccessToken" keys={keys} />
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Target Organization</label>
            <input
              type="text"
              className="textInput"
              value={data.githubTargetOrg}
              onChange={(e) => updateField('githubTargetOrg', e.target.value)}
              placeholder="organization-name"
              disabled={!tokenSet}
            />
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Target Repositories</label>
            <input
              type="text"
              className="textInput"
              value={data.githubTargetRepos}
              onChange={(e) => updateField('githubTargetRepos', e.target.value)}
              placeholder="repo1, repo2, repo3"
              disabled={!tokenSet}
            />
            <span className={styles.fieldHint}>
              Comma-separated list. Leave empty to scan all repositories.
            </span>
          </div>

          {tokenSet && (
            <>
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Scan Options</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Scan Member Repositories</span>
                    <p className={styles.toggleDescription}>Include repositories of organization members</p>
                  </div>
                  <Toggle
                    checked={data.githubScanMembers}
                    onChange={(checked) => updateField('githubScanMembers', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Scan Gists</span>
                    <p className={styles.toggleDescription}>Search for secrets in gists</p>
                  </div>
                  <Toggle
                    checked={data.githubScanGists}
                    onChange={(checked) => updateField('githubScanGists', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Scan Commits</span>
                    <p className={styles.toggleDescription}>Search commit history for secrets</p>
                    <TimeEstimate estimate="Most expensive operation - disabling saves 50%+ time" />
                  </div>
                  <Toggle
                    checked={data.githubScanCommits}
                    onChange={(checked) => updateField('githubScanCommits', checked)}
                  />
                </div>
              </div>

              {data.githubScanCommits && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Commits to Scan</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.githubMaxCommits}
                    onChange={(e) => updateField('githubMaxCommits', parseInt(e.target.value) || 100)}
                    min={1}
                    max={1000}
                  />
                  <span className={styles.fieldHint}>Number of commits to scan per repository</span>
                  <TimeEstimate estimate="Scales linearly: 100 = default, 1000 = ~10x slower" />
                </div>
              )}

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Output as JSON</span>
                  <p className={styles.toggleDescription}>Save results in JSON format</p>
                </div>
                <Toggle
                  checked={data.githubOutputJson}
                  onChange={(checked) => updateField('githubOutputJson', checked)}
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
