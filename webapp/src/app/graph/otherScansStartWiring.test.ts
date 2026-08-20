/**
 * Starting a scan from Other Scans must leave the operator looking at its logs.
 *
 * The logs drawer opens UNDER the modal, so a start that only opened the drawer
 * looked like it did nothing: the modal stayed up, still showing the card the
 * button was on. Each successful start therefore closes the modal as well - and
 * only on success, because a refused start needs the modal (and its queue
 * dialog) to stay where it is.
 *
 * Source-level, like tableViewWiring.test.ts: rendering /graph needs providers,
 * a router and live scan data, none of which is what is being checked.
 *
 * Run: npx vitest run src/app/graph/otherScansStartWiring.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const pageSrc = readFileSync(join(process.cwd(), 'src/app/graph/page.tsx'), 'utf8')

/** The body of one `const <name> = useCallback(...)` handler. */
function handler(name: string): string {
  const start = pageSrc.indexOf(`const ${name} = useCallback(`)
  expect(start, `${name} not found in page.tsx`).toBeGreaterThan(-1)
  const next = pageSrc.indexOf('\n  const ', start + 1)
  return pageSrc.slice(start, next === -1 ? undefined : next)
}

const STARTS = [
  { name: 'handleStartGithubHunt', drawer: "setActiveLogsDrawer('githubHunt')" },
  { name: 'handleStartTrufflehog', drawer: 'setActiveLogsDrawer(`trufflehog:${source}`)' },
  { name: 'handleStartSupplyChain', drawer: "setActiveLogsDrawer('supplyChain')" },
]

describe('Other Scans: starting a scan', () => {
  test.each(STARTS)('$name opens the logs drawer and closes the modal', ({ name, drawer }) => {
    const body = handler(name)
    expect(body).toContain(drawer)
    expect(body).toContain('setIsOtherScansModalOpen(false)')
  })

  test.each(STARTS)('$name closes the modal only on a successful start', ({ name }) => {
    const body = handler(name)
    // Both live inside the `if (result)` branch; a close outside it would also
    // fire when the start was refused and the queue dialog is about to open.
    const success = body.indexOf('if (result)')
    expect(success, `${name} no longer guards on the start result`).toBeGreaterThan(-1)
    expect(body.indexOf('setIsOtherScansModalOpen(false)')).toBeGreaterThan(success)
  })
})
