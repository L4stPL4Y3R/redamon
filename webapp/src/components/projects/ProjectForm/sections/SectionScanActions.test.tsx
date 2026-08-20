/**
 * Update Settings / Start to Scan on a scan section's header.
 *
 * The header IS the collapse toggle, so the thing that must not regress is the
 * stopPropagation: without it every click folds the section shut behind the
 * action it just triggered. Update Settings also mirrors the top bar's button,
 * including being dead while there is nothing to save.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { SectionScanActions } from './SectionScanActions'

afterEach(cleanup)

function renderInHeader(extra: Partial<Parameters<typeof SectionScanActions>[0]> = {}) {
  const onUpdateSettings = vi.fn()
  const onStartScan = vi.fn()
  const onHeaderClick = vi.fn()
  render(
    <div onClick={onHeaderClick}>
      <SectionScanActions
        onUpdateSettings={onUpdateSettings}
        onStartScan={onStartScan}
        scanLabel="Other Scans"
        isDirty
        isSubmitting={false}
        {...extra}
      />
    </div>
  )
  const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement
  return { onUpdateSettings, onStartScan, onHeaderClick, button }
}

describe('SectionScanActions', () => {
  test('each button runs its own action', () => {
    const { onUpdateSettings, onStartScan, button } = renderInHeader()
    fireEvent.click(button('Update Settings'))
    expect(onUpdateSettings).toHaveBeenCalledTimes(1)
    expect(onStartScan).not.toHaveBeenCalled()

    fireEvent.click(button('Start to Scan'))
    expect(onStartScan).toHaveBeenCalledTimes(1)
  })

  test('neither click reaches the header, so the section stays open', () => {
    const { onHeaderClick, button } = renderInHeader()
    fireEvent.click(button('Update Settings'))
    fireEvent.click(button('Start to Scan'))
    expect(onHeaderClick).not.toHaveBeenCalled()
  })

  test('Update Settings is dead with nothing to save; Start to Scan is not', () => {
    const { button } = renderInHeader({ isDirty: false })
    expect(button('Update Settings').disabled).toBe(true)
    expect(button('Update Settings').title).toBe('No unsaved changes')

    // Starting a scan on already-saved settings is exactly the normal case.
    expect(button('Start to Scan').disabled).toBe(false)
  })

  test('a save in flight disables both', () => {
    const { button } = renderInHeader({ isSubmitting: true })
    expect(button('Update Settings').disabled).toBe(true)
    expect(button('Start to Scan').disabled).toBe(true)
  })

  // It saves AND leaves for the graph, like the header button it mirrors, so the
  // tooltip has to say the second half too.
  test('Update Settings admits that it navigates away', () => {
    const { button } = renderInHeader()
    expect(button('Update Settings').title)
      .toBe('Save all changes and open the graph page - the header button, from here')
  })

  test('the scan button names what it will open', () => {
    const { button } = renderInHeader({ scanLabel: 'the GVM scan' })
    expect(button('Start to Scan').title).toBe('Save the settings and open the GVM scan on the graph page')
  })
})
