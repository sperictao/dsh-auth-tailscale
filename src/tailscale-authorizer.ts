import type {
  ConnectionAuthorizationDecision,
  ConnectionRequestAuthorizer,
  ConnectionRequestFacts,
} from '@dsh-external/dsh-client-connection-authz'
import { decodeRfc2047Header } from './rfc2047.ts'

const LOGIN_HEADER = 'tailscale-user-login'
const NAME_HEADER = 'tailscale-user-name'
const CAPABILITIES_HEADER = 'tailscale-app-capabilities'
const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor'])

export interface TailscaleAuthorizerConfig {
  readonly allowedLogins: string[]
  readonly useCapability?: string
  readonly adminCapability?: string
}

/** Exact-login and App-Capability policy for Tailscale Serve identity headers. */
export class TailscaleConnectionAuthorizer implements ConnectionRequestAuthorizer {
  private readonly allowedLogins: ReadonlySet<string>
  private readonly useCapability: string | undefined
  private readonly adminCapability: string | undefined

  constructor(config: TailscaleAuthorizerConfig) {
    this.allowedLogins = validatedAllowedLogins(config.allowedLogins)
    this.useCapability = validatedCapability(config.useCapability)
    this.adminCapability = validatedCapability(config.adminCapability)
  }

  authorize(facts: ConnectionRequestFacts): ConnectionAuthorizationDecision {
    const rawLogin = facts.headers.get(LOGIN_HEADER)
    if (rawLogin === undefined) return { allowed: false, status: 401 }

    let login: string
    let displayName: string | undefined
    try {
      login = decodeRfc2047Header(rawLogin)
      if (login.length === 0) return { allowed: false, status: 401 }
      const rawName = facts.headers.get(NAME_HEADER)
      if (rawName !== undefined) {
        displayName = decodeRfc2047Header(rawName)
        if (displayName.length === 0) return { allowed: false, status: 401 }
      }
    } catch {
      return { allowed: false, status: 401 }
    }

    if (!this.allowedLogins.has(login)) return { allowed: false, status: 403 }

    let capabilities: ReadonlySet<string>
    try {
      capabilities = parseCapabilities(facts.headers.get(CAPABILITIES_HEADER))
    } catch {
      return { allowed: false, status: 403 }
    }

    if (this.useCapability !== undefined && !capabilities.has(this.useCapability)) {
      return { allowed: false, status: 403 }
    }
    if (facts.requiredAuthority === 'loopback'
      && (this.adminCapability === undefined || !capabilities.has(this.adminCapability))) {
      return { allowed: false, status: 403 }
    }

    return {
      allowed: true,
      principal: {
        provider: 'tailscale',
        subject: login,
        ...(displayName === undefined ? {} : { displayName }),
        capabilities: [...capabilities].sort(),
      },
    }
  }
}

function validatedAllowedLogins(logins: readonly string[]): ReadonlySet<string> {
  if (!Array.isArray(logins) || logins.length === 0) {
    throw new Error('tailscale auth: allowedLogins must contain at least one login')
  }
  const result = new Set<string>()
  for (const login of logins) {
    if (login.length === 0) throw new Error('tailscale auth: allowedLogins cannot contain an empty login')
    if (login.trim() !== login) throw new Error('tailscale auth: allowedLogins cannot contain surrounding whitespace')
    if (!PLAIN_HEADER_VALUE.test(login)) throw new Error('tailscale auth: allowedLogins must use plain printable values')
    if (result.has(login)) throw new Error(`tailscale auth: duplicate allowed login ${JSON.stringify(login)}`)
    result.add(login)
  }
  return result
}

const PLAIN_HEADER_VALUE = /^[\x20-\x7e]+$/

function validatedCapability(capability: string | undefined): string | undefined {
  if (capability === undefined) return undefined
  if (capability.length === 0 || capability.trim() !== capability
    || !PLAIN_HEADER_VALUE.test(capability) || DANGEROUS_KEYS.has(capability)) {
    throw new Error(`tailscale auth: invalid capability ${JSON.stringify(capability)}`)
  }
  return capability
}

function parseCapabilities(rawHeader: string | undefined): ReadonlySet<string> {
  if (rawHeader === undefined) return new Set()
  const value: unknown = JSON.parse(decodeRfc2047Header(rawHeader))
  if (!isPlainObject(value)) throw new Error('Tailscale capabilities must be an object')

  const result = new Set<string>()
  for (const [capability, grants] of Object.entries(value)) {
    if (capability.length === 0 || DANGEROUS_KEYS.has(capability)) {
      throw new Error('Tailscale capabilities contain an invalid key')
    }
    if (!Array.isArray(grants) || grants.length === 0 || !grants.every(isPlainObject)) {
      throw new Error(`Tailscale capability ${JSON.stringify(capability)} has invalid grants`)
    }
    result.add(capability)
  }
  return result
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object'
    && value !== null
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
}
