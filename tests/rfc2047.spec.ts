import { describe, expect, it } from 'vitest'
import { decodeRfc2047Header } from '../src/rfc2047.ts'

describe('RFC 2047 header decoding', () => {
  it('keeps plain ASCII values unchanged', () => {
    expect(decodeRfc2047Header('alice@example.com')).toBe('alice@example.com')
  })

  it('decodes UTF-8 Q words and joins adjacent encoded words', () => {
    expect(decodeRfc2047Header('=?UTF-8?Q?Alice_=E9=99=88?=')).toBe('Alice 陈')
    expect(decodeRfc2047Header('=?utf-8?q?Alice_?= =?UTF-8?Q?=E9=99=88?=')).toBe('Alice 陈')
  })

  it.each([
    '=?ISO-8859-1?Q?Alice?=',
    '=?UTF-8?B?QWxpY2U=?=',
    '=?UTF-8?Q?broken=G0?=',
    'prefix =?UTF-8?Q?Alice?=',
    '=?UTF-8?Q?unterminated',
    'Alice\nAdmin',
    '直接 UTF-8',
  ])('rejects unsupported or ambiguous input %j', (value) => {
    expect(() => decodeRfc2047Header(value)).toThrow()
  })
})
