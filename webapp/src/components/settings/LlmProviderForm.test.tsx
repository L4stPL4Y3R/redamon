/**
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

const toastSuccess = vi.fn()
const toastError = vi.fn()

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: toastSuccess, error: toastError }),
  // The form also reaches for the alert modal; mocking the module wholesale
  // means every hook it uses has to be listed here or the render throws.
  useAlertModal: () => ({
    alert: vi.fn(async () => {}),
    alertError: vi.fn(async () => {}),
    alertWarning: vi.fn(async () => {}),
    confirm: vi.fn(async () => true),
    dangerConfirm: vi.fn(async () => true),
  }),
}))

import { LlmProviderForm } from './LlmProviderForm'
import type { ProviderData } from './LlmProviderForm'

const PROVIDER: ProviderData = {
  id: 'ollama-provider',
  providerType: 'openai_compatible',
  name: 'Ollama Gemma 4',
  apiKey: '',
  baseUrl: 'http://host.docker.internal:11434/v1',
  modelIdentifier: 'gemma4:latest',
  defaultHeaders: {},
  timeout: 120,
  temperature: 0,
  maxTokens: 16384,
  sslVerify: true,
  reasoningEnabled: false,
  reasoningEffort: 'high',
  awsRegion: 'us-east-1',
  awsAccessKeyId: '',
  awsSecretKey: '',
  awsBearerToken: '',
}

describe('LlmProviderForm Ollama reasoning control', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
  })

  test('enables the effort selector and persists the selected level', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({}),
    } as Response)
    const onSave = vi.fn()

    render(
      <LlmProviderForm
        userId="user-1"
        provider={PROVIDER}
        onSave={onSave}
        onCancel={vi.fn()}
      />,
    )

    const toggle = screen.getByRole('checkbox', { name: 'Enable reasoning effort' })
    const effort = screen.getByRole('combobox', { name: 'Reasoning effort' })
    expect(toggle).not.toBeChecked()
    expect(effort).toBeDisabled()

    fireEvent.click(toggle)
    expect(effort).toBeEnabled()
    fireEvent.change(effort, { target: { value: 'medium' } })
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const request = fetchMock.mock.calls[0][1] as RequestInit
    const body = JSON.parse(request.body as string)
    expect(body.reasoningEnabled).toBe(true)
    expect(body.reasoningEffort).toBe('medium')
    expect(onSave).toHaveBeenCalled()
  })
})

// Issue #173: the save failed with a server-side reason the form threw away,
// leaving the user with an unactionable "Failed to save provider".
describe('LlmProviderForm save errors', () => {
  beforeEach(() => {
    // Auto-cleanup is off (vitest globals are not enabled), so an earlier
    // render would leave a second "Update Provider" button in the document.
    cleanup()
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
  })
  afterEach(cleanup)

  test('surfaces the API error message instead of the blanket one', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 404,
      json: async () => ({ error: 'User not found. Log out and back in.' }),
    } as Response)
    const onSave = vi.fn()

    render(
      <LlmProviderForm userId="ghost" provider={PROVIDER} onSave={onSave} onCancel={vi.fn()} />,
    )
    // Save stays disabled until the form is dirty (useDirtyState).
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable reasoning effort' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('User not found. Log out and back in.'))
    expect(onSave).not.toHaveBeenCalled()
  })

  test('a non-JSON error body still yields a message with the status code', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 502,
      json: async () => { throw new SyntaxError('Unexpected token <') },
    } as unknown as Response)

    render(
      <LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable reasoning effort' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Failed to save provider (HTTP 502)'))
  })
})
