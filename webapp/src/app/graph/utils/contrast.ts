/**
 * Readable text on top of a node colour.
 *
 * Badges paint a node's palette colour as their background, and the palette in
 * `config/colors.ts` is the identity of each node type on the canvas, so it is
 * fixed input here: the TEXT moves, not the background. White-on-everything
 * failed WCAG AA on 18 of the 43 node colours (Capec yellow sat at 1.9:1);
 * picking whichever of white/near-black scores higher clears AA for all but one.
 *
 * The background is nudged darker only in that leftover case, where neither text
 * colour clears the bar because the colour sits at mid luminance. The nudge is
 * a few percent, far too small to read as a different colour.
 */

/** WCAG AA for text below 18px, which every badge in the app is. */
const TARGET_RATIO = 4.5

export const BADGE_LIGHT_TEXT = '#ffffff'
/** Matches the canvas background, so dark badge text belongs to the same ink. */
export const BADGE_DARK_TEXT = '#0a0a0a'

const DARKEN_STEP = 0.94
const MAX_DARKEN_STEPS = 12

type Rgb = [number, number, number]

const parseHex = (hex: string): Rgb | null => {
  const value = hex.trim().replace(/^#/, '')
  const full = value.length === 3 ? value.replace(/./g, c => c + c) : value
  if (!/^[0-9a-fA-F]{6}$/.test(full)) return null
  return [
    parseInt(full.slice(0, 2), 16),
    parseInt(full.slice(2, 4), 16),
    parseInt(full.slice(4, 6), 16),
  ]
}

const toHex = ([r, g, b]: Rgb): string =>
  '#' + [r, g, b].map(c => Math.round(c).toString(16).padStart(2, '0')).join('')

const linearize = (channel: number): number => {
  const c = channel / 255
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
}

/** WCAG relative luminance. Returns null for anything that is not a hex colour. */
export const relativeLuminance = (hex: string): number | null => {
  const rgb = parseHex(hex)
  if (!rgb) return null
  const [r, g, b] = rgb.map(linearize)
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** WCAG contrast ratio between two hex colours, 1 (identical) to 21 (black/white). */
export const contrastRatio = (a: string, b: string): number => {
  const la = relativeLuminance(a)
  const lb = relativeLuminance(b)
  if (la === null || lb === null) return 1
  const [hi, lo] = la > lb ? [la, lb] : [lb, la]
  return (hi + 0.05) / (lo + 0.05)
}

/** The higher-contrast of white / near-black against `background`. */
export const readableTextColor = (background: string): string =>
  contrastRatio(background, BADGE_DARK_TEXT) > contrastRatio(background, BADGE_LIGHT_TEXT)
    ? BADGE_DARK_TEXT
    : BADGE_LIGHT_TEXT

export interface BadgeColors {
  /** The palette colour, darkened only when no text colour could clear AA on it. */
  background: string
  color: string
}

/**
 * Background + text for a badge that fills itself with a node colour. Feed it
 * whatever `getNodeColor` / `NODE_COLORS` returned; a non-hex value (a CSS
 * variable, a gradient) passes through with white text, as before.
 */
export const badgeColors = (background: string): BadgeColors => {
  const rgb = parseHex(background)
  if (!rgb) return { background, color: BADGE_LIGHT_TEXT }

  const text = readableTextColor(background)
  if (contrastRatio(background, text) >= TARGET_RATIO) return { background, color: text }

  // Mid-luminance colour: too dark for black text, too light for white. Walk it
  // toward black until white text clears AA.
  let current = rgb
  for (let step = 0; step < MAX_DARKEN_STEPS; step++) {
    current = current.map(c => c * DARKEN_STEP) as Rgb
    const darkened = toHex(current)
    if (contrastRatio(darkened, BADGE_LIGHT_TEXT) >= TARGET_RATIO) {
      return { background: darkened, color: BADGE_LIGHT_TEXT }
    }
  }
  return { background: toHex(current), color: BADGE_LIGHT_TEXT }
}
