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
  allowedLogins: z.array(z.string().min(1)).default([]),
  useCapability: z.string().min(1),
  adminCapability: z.string().min(1),
})

/** Provide the required authorizer; Connection itself stays provider-agnostic. */
export function apply(ctx: Context, config: TailscaleAuthorizerConfig): void {
  if (config.allowedLogins.length === 0) {
    // cordis logger 默认只进内存缓冲，终端裸跑看不见；启动提示必须走 console
    console.warn(
      '[dsh-auth-tailscale] allowedLogins is empty, every remote connection will be denied;'
      + ' set DSH_TAILSCALE_ALLOWED_LOGINS (or configure remote access in DSH Pro Max) to allow logins',
    )
  }
  ctx.provide('connectionRequestAuthorizer', new TailscaleConnectionAuthorizer(config))
}
