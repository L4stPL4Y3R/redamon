/**
 * TruffleHog section: the Concurrency number box.
 *
 * Regression. The field was `parseInt(e.target.value) || 8`, so clearing it
 * produced NaN, fell back to 8, and re-rendered 8 into the box on the same
 * keystroke. The value could never be emptied, only appended to: selecting the
 * 8 and typing 5 left you with 85, not 5.
 *
 * The bug only exists across the controlled round-trip, so these tests drive
 * the section through a stateful parent that feeds updateField back in as
 * `data` — exactly what ProjectForm does. With a frozen `data` prop the
 * assertions below would pass against the broken code.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/TrufflehogSection.concurrency.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { useState } from 'react'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { TrufflehogSection } from './TrufflehogSection'

// vitest runs without `globals: true`, so RTL's auto-cleanup never registers.
afterEach(() => cleanup())

/** Create mode renders the shared options and skips the profile fetch. */
function Harness({ initial, onChange }: { initial: number; onChange: (v: unknown) => void }) {
  const [data, setData] = useState<Record<string, unknown>>({ trufflehogConcurrency: initial })
  return (
    <TrufflehogSection
      data={data as never}
      updateField={((key: string, value: unknown) => {
        onChange(value)
        setData((d) => ({ ...d, [key]: value }))
      }) as never}
      mode="create"
      projectId={null}
    />
  )
}

function renderConcurrency(initial = 8) {
  const onChange = vi.fn()
  render(<Harness initial={initial} onChange={onChange} />)
  const input = screen.getByLabelText('Concurrency') as HTMLInputElement
  return { input, onChange, stored: () => onChange.mock.calls.at(-1)?.[0] }
}

describe('TrufflehogSection concurrency', () => {
  test('renders the stored value', () => {
    const { input } = renderConcurrency(12)
    expect(input.value).toBe('12')
  })

  test('the box can be emptied instead of snapping back to the default', () => {
    const { input } = renderConcurrency(8)
    fireEvent.change(input, { target: { value: '' } })
    expect(input.value).toBe('')
  })

  test('clearing keeps the last valid number stored, never NaN', () => {
    const { input, onChange, stored } = renderConcurrency(8)
    fireEvent.change(input, { target: { value: '' } })
    // Either nothing was written, or what was written is still the old number.
    if (onChange.mock.calls.length > 0) expect(stored()).toBe(8)
    expect(stored() ?? 8).not.toBeNaN()
  })

  test('retyping after a clear replaces the value rather than appending', () => {
    const { input, stored } = renderConcurrency(8)
    fireEvent.change(input, { target: { value: '' } })
    fireEvent.change(input, { target: { value: '5' } })
    expect(input.value).toBe('5')
    expect(stored()).toBe(5)
  })

  test('a value above the max is clamped, since min/max do not bind typed input', () => {
    const { input, stored } = renderConcurrency(8)
    fireEvent.change(input, { target: { value: '81' } })
    expect(stored()).toBe(32)
  })

  test('a value below the min is clamped', () => {
    const { input, stored } = renderConcurrency(8)
    fireEvent.change(input, { target: { value: '0' } })
    expect(stored()).toBe(1)
  })

  test('blurring an empty box restores the stored value to the display', () => {
    const { input } = renderConcurrency(8)
    fireEvent.change(input, { target: { value: '' } })
    fireEvent.blur(input)
    expect(input.value).toBe('8')
  })
})
