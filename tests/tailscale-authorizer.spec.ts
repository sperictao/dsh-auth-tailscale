import { describe, expect, it } from 'vitest'
import type {
  ConnectionRequestAuthority,
  ConnectionRequestFacts,
} from '@dsh-external/dsh-client-connection-authz'
import { TailscaleConnectionAuthorizer } from '../src/tailscale-authorizer.ts'

function facts(
  headers: Record<string, string>,
  requiredAuthority: ConnectionRequestAuthority = 'trusted-host',
): ConnectionRequestFacts {
  const values = new Headers(headers)
  return {
    transport: 'http',
    channel: '/api',
    endpoint: 'session.list',
    requiredAuthority,
    headers: { get: name => values.get(name) ?? undefined },
    peerAddress: '127.0.0.1',
  }
}

describe('TailscaleConnectionAuthorizer', () => {
  it('requires an injected Tailscale login and an exact allowlist match', () => {
    const authorizer = new TailscaleConnectionAuthorizer({ allowedLogins: ['alice@example.com'] })
    expect(authorizer.authorize(facts({}))).toEqual({ allowed: false, status: 401 })
    expect(authorizer.authorize(facts({ 'tailscale-user-login': 'Alice@example.com' })))
      .toEqual({ allowed: false, status: 403 })
    expect(authorizer.authorize(facts({ 'tailscale-user-login': 'mallory@example.com' })))
      .toEqual({ allowed: false, status: 403 })
  })

  it('returns the decoded Tailscale identity as the principal', () => {
    const authorizer = new TailscaleConnectionAuthorizer({ allowedLogins: ['alice@example.com'] })
    expect(authorizer.authorize(facts({
      'tailscale-user-login': 'alice@example.com',
      'tailscale-user-name': '=?UTF-8?Q?Alice_=E9=99=88?=',
    }))).toEqual({
      allowed: true,
      principal: {
        provider: 'tailscale',
        subject: 'alice@example.com',
        displayName: 'Alice 陈',
        capabilities: [],
      },
    })
  })

  it('rejects malformed encoded identity headers', () => {
    const authorizer = new TailscaleConnectionAuthorizer({ allowedLogins: ['alice@example.com'] })
    expect(authorizer.authorize(facts({
      'tailscale-user-login': '=?UTF-8?Q?alice@example.com',
    }))).toEqual({ allowed: false, status: 401 })
  })

  it('requires the configured ordinary-use capability', () => {
    const authorizer = new TailscaleConnectionAuthorizer({
      allowedLogins: ['alice@example.com'],
      useCapability: 'example.com/cap/dsh',
    })
    const identity = { 'tailscale-user-login': 'alice@example.com' }
    expect(authorizer.authorize(facts(identity))).toEqual({ allowed: false, status: 403 })
    expect(authorizer.authorize(facts({
      ...identity,
      'tailscale-app-capabilities': JSON.stringify({ 'example.com/cap/dsh': [{}] }),
    }))).toMatchObject({ allowed: true })
  })

  it('decodes the RFC 2047 capability JSON emitted for non-ASCII grants', () => {
    const authorizer = new TailscaleConnectionAuthorizer({
      allowedLogins: ['alice@example.com'],
      useCapability: 'example.com/cap/dsh',
    })
    expect(authorizer.authorize(facts({
      'tailscale-user-login': 'alice@example.com',
      'tailscale-app-capabilities': '=?utf-8?q?{"example.com/cap/dsh":[{"role":"=F0=9F=90=BF=EF=B8=8F"}]}?=',
    }))).toMatchObject({
      allowed: true,
      principal: { capabilities: ['example.com/cap/dsh'] },
    })
  })

  it('requires a separate admin capability for loopback-authority endpoints', () => {
    const identity = { 'tailscale-user-login': 'alice@example.com' }
    const noAdmin = new TailscaleConnectionAuthorizer({ allowedLogins: ['alice@example.com'] })
    expect(noAdmin.authorize(facts(identity, 'loopback'))).toEqual({ allowed: false, status: 403 })

    const withAdmin = new TailscaleConnectionAuthorizer({
      allowedLogins: ['alice@example.com'],
      adminCapability: 'example.com/cap/dsh-admin',
    })
    expect(withAdmin.authorize(facts(identity, 'loopback'))).toEqual({ allowed: false, status: 403 })
    expect(withAdmin.authorize(facts({
      ...identity,
      'tailscale-app-capabilities': JSON.stringify({ 'example.com/cap/dsh-admin': [{ role: 'admin' }] }),
    }, 'loopback'))).toMatchObject({ allowed: true })
  })

  it.each([
    '{',
    '[]',
    '{"example.com/cap/dsh":[]}',
    '{"example.com/cap/dsh":[null]}',
    '{"__proto__":[{}]}',
  ])('rejects malformed capability data %s', (capabilities) => {
    const authorizer = new TailscaleConnectionAuthorizer({ allowedLogins: ['alice@example.com'] })
    expect(authorizer.authorize(facts({
      'tailscale-user-login': 'alice@example.com',
      'tailscale-app-capabilities': capabilities,
    }))).toEqual({ allowed: false, status: 403 })
  })

  it('fails loudly on empty, duplicate, or ambiguous configuration', () => {
    expect(() => new TailscaleConnectionAuthorizer({ allowedLogins: [] })).toThrow(/allowedLogins/)
    expect(() => new TailscaleConnectionAuthorizer({
      allowedLogins: ['alice@example.com', 'alice@example.com'],
    })).toThrow(/duplicate/)
    expect(() => new TailscaleConnectionAuthorizer({
      allowedLogins: [' alice@example.com'],
    })).toThrow(/whitespace/)
    expect(() => new TailscaleConnectionAuthorizer({
      allowedLogins: ['alice@example.com'],
      adminCapability: '__proto__',
    })).toThrow(/capability/)
  })
})
