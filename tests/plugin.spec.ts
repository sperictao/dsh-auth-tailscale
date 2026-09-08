import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import { apply, Config } from '../src/index.ts'

describe('Cordis provider plugin', () => {
  it('accepts an empty allowlist in the config schema (deny-all)', () => {
    expect(Config({ allowedLogins: [] })).toMatchObject({ allowedLogins: [] })
  })
  it('provides and withdraws connectionRequestAuthorizer with its fiber', async () => {
    const ctx = new Context()
    const fiber = ctx.plugin({ apply }, { allowedLogins: ['alice@example.com'] })
    await fiber.await()
    expect(ctx.get('connectionRequestAuthorizer')).toBeDefined()
    await fiber.dispose()
    expect(ctx.get('connectionRequestAuthorizer')).toBeUndefined()
  })

  it('boots with an empty allowlist (deny-all) instead of failing config validation', async () => {
    const ctx = new Context()
    const fiber = ctx.plugin({ apply }, { allowedLogins: [] })
    await fiber.await()
    expect(ctx.get('connectionRequestAuthorizer')).toBeDefined()
    await fiber.dispose()
  })
})
