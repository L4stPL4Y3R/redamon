/**
 * useReports Hook
 *
 * TanStack Query hooks for fetching, generating, and deleting reports.
 * Supports both project-specific and all-projects modes.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export interface ReportMeta {
  id: string
  projectId: string
  title: string
  filename: string
  fileSize: number
  format: string
  metrics: {
    riskScore?: number
    riskLabel?: string
    totalVulnerabilities?: number
    totalCves?: number
    criticalCount?: number
    highCount?: number
    mediumCount?: number
    lowCount?: number
    cveCriticalCount?: number
    cveHighCount?: number
    cveMediumCount?: number
    cveLowCount?: number
    totalRemediations?: number
    exploitableCount?: number
  }
  hasNarratives: boolean
  createdAt: string
  project?: {
    id: string
    name: string
    targetDomain?: string
  }
}

const REPORTS_KEY = 'reports'
const ALL_REPORTS_KEY = 'all-reports'

async function fetchReports(projectId: string): Promise<ReportMeta[]> {
  const res = await fetch(`/api/projects/${projectId}/reports`)
  if (!res.ok) throw new Error('Failed to fetch reports')
  return res.json()
}

async function fetchAllReports(): Promise<ReportMeta[]> {
  const res = await fetch('/api/reports')
  if (!res.ok) throw new Error('Failed to fetch reports')
  return res.json()
}

async function generateReport(projectId: string): Promise<ReportMeta> {
  const res = await fetch(`/api/projects/${projectId}/reports`, { method: 'POST' })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || 'Report generation failed')
  }
  return res.json()
}

async function deleteReport(projectId: string, reportId: string): Promise<void> {
  const res = await fetch(`/api/projects/${projectId}/reports/${reportId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete report')
}

/** Hook for project-specific reports */
export function useReports(projectId: string, enabled = true) {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: [REPORTS_KEY, projectId],
    queryFn: () => fetchReports(projectId),
    enabled: enabled && !!projectId,
    staleTime: 30_000,
  })

  const generateMutation = useMutation({
    mutationFn: () => generateReport(projectId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REPORTS_KEY, projectId] })
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (reportId: string) => deleteReport(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REPORTS_KEY, projectId] })
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  return {
    reports: query.data ?? [],
    isLoading: query.isLoading,
    error: query.error,
    generate: generateMutation.mutateAsync,
    isGenerating: generateMutation.isPending,
    generateError: generateMutation.error,
    deleteReport: deleteMutation.mutate,
    isDeleting: deleteMutation.isPending,
  }
}

/** Hook for all-projects reports listing */
export function useAllReports() {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: [ALL_REPORTS_KEY],
    queryFn: fetchAllReports,
    staleTime: 30_000,
  })

  const deleteMutation = useMutation({
    mutationFn: ({ projectId, reportId }: { projectId: string; reportId: string }) =>
      deleteReport(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  const generateMutation = useMutation({
    mutationFn: (projectId: string) => generateReport(projectId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  return {
    reports: query.data ?? [],
    isLoading: query.isLoading,
    error: query.error,
    generate: generateMutation.mutateAsync,
    isGenerating: generateMutation.isPending,
    generateError: generateMutation.error,
    deleteReport: deleteMutation.mutate,
    isDeleting: deleteMutation.isPending,
  }
}
