import { describe, test, expect } from 'vitest'
import { classifyStartFailure } from './scanStartOutcome'

describe('classifyStartFailure', () => {
  test('RAM limit is temporary with code ram', () => {
    const c = classifyStartFailure(429, { error: 'no mem', limit: { limitType: 'ram' } })
    expect(c).toMatchObject({ kind: 'temporary', temporary: true, blockedCode: 'ram' })
  })

  test('hard limit is temporary with code hard', () => {
    const c = classifyStartFailure(429, { error: 'max concurrent', limit: { limitType: 'hard' } })
    expect(c).toMatchObject({ kind: 'temporary', temporary: true, blockedCode: 'hard' })
  })

  test('activationInProgress is temporary with code activating', () => {
    const c = classifyStartFailure(409, { error: 'activating', activationInProgress: true })
    expect(c).toMatchObject({ kind: 'temporary', blockedCode: 'activating' })
  })

  test('any bare 409 (no limit, plain string) is temporary/busy', () => {
    const c = classifyStartFailure(409, { error: 'Cannot start a scan while a full recon scan is running' })
    expect(c).toMatchObject({ kind: 'temporary', temporary: true, blockedCode: 'busy' })
    expect(typeof c.reason).toBe('string')
  })

  test('400 is permanent', () => {
    expect(classifyStartFailure(400, { error: 'no target' })).toMatchObject({ kind: 'permanent', temporary: false, blockedCode: '' })
  })

  test('404 is permanent', () => {
    expect(classifyStartFailure(404, { error: 'gone' }).temporary).toBe(false)
  })

  test('500 is permanent', () => {
    expect(classifyStartFailure(500, { error: 'boom' }).temporary).toBe(false)
  })

  test('missing body never throws and yields a string reason', () => {
    const c = classifyStartFailure(undefined, undefined)
    expect(c.kind).toBe('permanent')
    expect(typeof c.reason).toBe('string')
  })

  test('a RAM limit wins even if status is not 409', () => {
    expect(classifyStartFailure(200, { limit: { limitType: 'ram' } }).blockedCode).toBe('ram')
  })
})
