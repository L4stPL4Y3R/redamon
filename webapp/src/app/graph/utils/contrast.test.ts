/**
 * Badges paint a node colour behind text, so the readable-text rule has to hold
 * for EVERY colour in the palette, not just the ones on screen today. The loop
 * over NODE_COLORS is the point of this file: adding a node type with a badly
 * contrasting colour fails here instead of shipping an unreadable badge.
 *
 * Run: npx vitest run src/app/graph/utils/contrast.test.ts
 */

import { describe, test, expect } from 'vitest'
import {
  badgeColors,
  contrastRatio,
  readableTextColor,
  relativeLuminance,
  BADGE_DARK_TEXT,
  BADGE_LIGHT_TEXT,
} from './contrast'
import {
  NODE_COLORS,
  SEVERITY_COLORS_VULN,
  SEVERITY_COLORS_CVE,
  CHAIN_SESSION_COLORS,
  GOAL_FINDING_COLORS,
} from '../config/colors'

const AA = 4.5

describe('contrast primitives', () => {
  test('black on white is the 21:1 maximum, a colour on itself is 1:1', () => {
    expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 1)
    expect(contrastRatio('#3b82f6', '#3b82f6')).toBeCloseTo(1, 5)
  })

  test('luminance is null for anything that is not a hex colour', () => {
    expect(relativeLuminance('var(--node-domain)')).toBeNull()
    expect(relativeLuminance('rgb(1,2,3)')).toBeNull()
    expect(relativeLuminance('#12345')).toBeNull()
  })

  test('shorthand hex is expanded, not rejected', () => {
    expect(relativeLuminance('#fff')).toBeCloseTo(relativeLuminance('#ffffff')!, 6)
  })
})

describe('readableTextColor', () => {
  test('bright colours take dark text', () => {
    expect(readableTextColor(NODE_COLORS.Capec)).toBe(BADGE_DARK_TEXT)      // yellow
    expect(readableTextColor(NODE_COLORS.Technology)).toBe(BADGE_DARK_TEXT) // green
    expect(readableTextColor(NODE_COLORS.ChainFinding)).toBe(BADGE_DARK_TEXT)
    expect(readableTextColor(NODE_COLORS.ChainStep)).toBe(BADGE_DARK_TEXT)
  })

  test('deep colours keep white text', () => {
    expect(readableTextColor(NODE_COLORS.Domain)).toBe(BADGE_LIGHT_TEXT)
    expect(readableTextColor(NODE_COLORS.Malware)).toBe(BADGE_LIGHT_TEXT)
    expect(readableTextColor(NODE_COLORS.ChainDecision)).toBe(BADGE_LIGHT_TEXT)
  })
})

describe('badgeColors', () => {
  const palettes: Record<string, Record<string, string>> = {
    NODE_COLORS,
    SEVERITY_COLORS_VULN,
    SEVERITY_COLORS_CVE,
    CHAIN_SESSION_COLORS,
    GOAL_FINDING_COLORS,
  }

  for (const [paletteName, palette] of Object.entries(palettes)) {
    test(`every ${paletteName} entry reaches WCAG AA behind badge text`, () => {
      const failures: string[] = []
      for (const [name, hex] of Object.entries(palette)) {
        const { background, color } = badgeColors(hex)
        const ratio = contrastRatio(background, color)
        if (ratio < AA) failures.push(`${name} ${hex} -> ${background}/${color} = ${ratio.toFixed(2)}`)
      }
      expect(failures).toEqual([])
    })
  }

  test('the palette colour is preserved whenever a text colour can clear AA', () => {
    // The background is the node's identity on the canvas; only a colour that no
    // text colour can sit on is allowed to move.
    const moved = Object.entries(NODE_COLORS).filter(
      ([, hex]) => badgeColors(hex).background !== hex,
    )
    expect(moved.map(([name]) => name)).toEqual(['BaseURL'])
  })

  test('a nudged background stays visually the same colour', () => {
    const { background, color } = badgeColors(NODE_COLORS.BaseURL)
    expect(color).toBe(BADGE_LIGHT_TEXT)
    expect(contrastRatio(background, BADGE_LIGHT_TEXT)).toBeGreaterThanOrEqual(AA)
    // A few percent darker, nowhere near a different hue.
    expect(contrastRatio(background, NODE_COLORS.BaseURL)).toBeLessThan(1.3)
  })

  test('non-hex input passes through untouched with white text', () => {
    expect(badgeColors('var(--node-domain)')).toEqual({
      background: 'var(--node-domain)',
      color: BADGE_LIGHT_TEXT,
    })
  })
})
