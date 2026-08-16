import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import { apply } from '../src/index.ts'

describe('Cordis provider plugin', () => {
  it('provides and withdraws connectionRequestAuthorizer with its fiber', async () => {
    const ctx = new Context()
    const fiber = ctx.plugin({ apply }, { allowedLogins: ['alice@example.com'] })
    await fiber.await()
    expect(ctx.get('connectionRequestAuthorizer')).toBeDefined()
    await fiber.dispose()
    expect(ctx.get('connectionRequestAuthorizer')).toBeUndefined()
  })
})
