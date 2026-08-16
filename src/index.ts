import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import {
  TailscaleConnectionAuthorizer,
  type TailscaleAuthorizerConfig,
} from './tailscale-authorizer.ts'

export { decodeRfc2047Header } from './rfc2047.ts'
export { TailscaleConnectionAuthorizer, type TailscaleAuthorizerConfig } from './tailscale-authorizer.ts'

export const name = 'dsh-auth-tailscale'

export const Config: z<TailscaleAuthorizerConfig> = z.object({
  allowedLogins: z.array(z.string().min(1)).min(1).required(),
  useCapability: z.string().min(1),
  adminCapability: z.string().min(1),
})

/** Provide the required authorizer; Connection itself stays provider-agnostic. */
export function apply(ctx: Context, config: TailscaleAuthorizerConfig): void {
  ctx.provide('connectionRequestAuthorizer', new TailscaleConnectionAuthorizer(config))
}
