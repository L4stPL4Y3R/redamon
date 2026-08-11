/**
 * Supply Chain Recon section: the Ecosystems multi-select.
 *
 * What this guards, beyond "it renders": the widget writes the SAME
 * comma-separated string the recon pipeline reads, in canonical casing, and it
 * tells the truth about what the current value does (empty = no filter, an
 * unrecognized token = a filter nothing can match, npm unticked = nothing
 * harvested is reported).
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/SupplyChainReconSection.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'
import { SupplyChainReconSection } from './SupplyChainReconSection'
import { SUPPLY_CHAIN_ECOSYSTEMS } from './supplyChainEcosystems'

type Data = Record<string, unknown>

// vitest runs without `globals: true`, so RTL's auto-cleanup never registers.
afterEach(() => cleanup())

function renderSection(overrides: Data = {}) {
  const updateField = vi.fn()
  const data = {
    supplyChainReconEnabled: true,
    supplyChainReconEcosystems: 'npm',
    supplyChainReconDeepAnalysisEnabled: false,
    ...overrides,
  }
  render(
    <SupplyChainReconSection
      data={data as never}
      updateField={updateField as never}
    />,
  )
  return { updateField }
}

/** The checkbox group only; the section has other checkbox-free toggles. */
function ecosystemGroup() {
  return screen.getByRole('group', { name: 'Ecosystems' })
}

function checkboxFor(label: RegExp) {
  return within(ecosystemGroup()).getByRole('checkbox', { name: label })
}

function checkedEcosystems() {
  return within(ecosystemGroup())
    .getAllByRole('checkbox')
    .filter((el) => (el as HTMLInputElement).checked)
    .map((el) => (el.closest('label') as HTMLElement).textContent?.trim())
}

describe('Ecosystems multi-select', () => {
  test('renders one checkbox per catalogue ecosystem', () => {
    renderSection()
    const boxes = within(ecosystemGroup()).getAllByRole('checkbox')
    expect(boxes).toHaveLength(SUPPLY_CHAIN_ECOSYSTEMS.length)
    for (const eco of SUPPLY_CHAIN_ECOSYSTEMS) {
      expect(within(ecosystemGroup()).getByText(new RegExp(`^${eco.replace('.', '\\.')}( |$)`)))
        .toBeInTheDocument()
    }
  })

  test('no free-text ecosystems input survives', () => {
    // Regression: the field used to be a comma-separated text box, which is how
    // non-canonical values ("pypi", "cargo") got stored in the first place.
    renderSection()
    expect(within(ecosystemGroup()).queryByRole('textbox')).toBeNull()
    expect(screen.queryByPlaceholderText('npm')).toBeNull()
  })

  test('the stored default ticks npm and nothing else', () => {
    renderSection()
    expect(checkedEcosystems()).toEqual(['npm (JavaScript)'])
  })

  test('ticking a second ecosystem writes both, in catalogue order', () => {
    const { updateField } = renderSection()
    fireEvent.click(checkboxFor(/^Go/))
    expect(updateField).toHaveBeenCalledWith('supplyChainReconEcosystems', 'npm,Go')
  })

  test('unticking the only ecosystem writes the empty (no-filter) string', () => {
    const { updateField } = renderSection()
    fireEvent.click(checkboxFor(/^npm/))
    expect(updateField).toHaveBeenCalledWith('supplyChainReconEcosystems', '')
  })

  test('a legacy free-text value ticks the right boxes despite casing and spaces', () => {
    renderSection({ supplyChainReconEcosystems: ' pypi , NPM ' })
    expect(checkedEcosystems()).toEqual(['npm (JavaScript)', 'PyPI (Python)'])
  })

  test('a legacy free-text value is canonicalized on the first toggle', () => {
    const { updateField } = renderSection({ supplyChainReconEcosystems: 'pypi' })
    fireEvent.click(checkboxFor(/^Go/))
    expect(updateField).toHaveBeenCalledWith('supplyChainReconEcosystems', 'PyPI,Go')
  })

  test('the section renders nothing configurable while the module is off', () => {
    renderSection({ supplyChainReconEnabled: false })
    expect(screen.queryByRole('group', { name: 'Ecosystems' })).toBeNull()
  })
})

describe('warnings tell the truth about the stored value', () => {
  test('empty value says no filter is applied', () => {
    renderSection({ supplyChainReconEcosystems: '' })
    expect(screen.getByText(/no filter is applied/i)).toBeInTheDocument()
    expect(screen.queryByText(/Not an OSV ecosystem/i)).toBeNull()
  })

  test('an unrecognized token is named, and is NOT reported as "no filter"', () => {
    // "cargo" is a live filter that matches nothing - the opposite of no filter.
    renderSection({ supplyChainReconEcosystems: 'cargo' })
    expect(screen.getByText(/Not an OSV ecosystem/i)).toHaveTextContent('cargo')
    expect(screen.queryByText(/no filter is applied/i)).toBeNull()
  })

  test('unrecognized tokens are listed even next to a valid selection', () => {
    renderSection({ supplyChainReconEcosystems: 'npm,cargo,rust' })
    expect(screen.getByText(/Not an OSV ecosystem/i)).toHaveTextContent('cargo, rust')
    expect(checkedEcosystems()).toEqual(['npm (JavaScript)'])
  })

  test('a selection without npm warns that nothing harvested is reported', () => {
    renderSection({ supplyChainReconEcosystems: 'PyPI,Go' })
    expect(screen.getByText(/harvests npm packages only/i)).toBeInTheDocument()
  })

  test('the npm-only warning stays away when npm is selected', () => {
    renderSection({ supplyChainReconEcosystems: 'npm,Go' })
    expect(screen.queryByText(/harvests npm packages only/i)).toBeNull()
    expect(screen.queryByText(/no filter is applied/i)).toBeNull()
  })
})
