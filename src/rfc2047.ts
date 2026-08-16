const ENCODED_WORD = /^=\?utf-8\?q\?([^?]*)\?=$/i
const PLAIN_ASCII = /^[\x20-\x7e]*$/
const HEADER_CONTROLS = /[\u0000-\u001f\u007f]/
const HEX_BYTE = /^[0-9a-f]{2}$/i

/** Decode the strict UTF-8 Q form emitted by Tailscale for non-ASCII headers. */
export function decodeRfc2047Header(value: string): string {
  if (!value.includes('=?')) {
    if (!PLAIN_ASCII.test(value)) throw new Error('header must be ASCII or RFC 2047 encoded')
    return value
  }

  const words = value.split(/[ \t]+/)
  if (words.length === 0 || words.some(word => word.length === 0)) {
    throw new Error('invalid RFC 2047 encoded words')
  }
  const decoded = words.map(decodeWord).join('')
  if (HEADER_CONTROLS.test(decoded)) throw new Error('decoded header contains a control character')
  return decoded
}

function decodeWord(word: string): string {
  const match = ENCODED_WORD.exec(word)
  if (match === null) throw new Error('unsupported RFC 2047 encoded word')
  const payload = match[1]!
  const bytes: number[] = []
  for (let index = 0; index < payload.length; index += 1) {
    const character = payload[index]!
    if (character === '_') {
      bytes.push(0x20)
      continue
    }
    if (character === '=') {
      const byte = payload.slice(index + 1, index + 3)
      if (!HEX_BYTE.test(byte)) throw new Error('invalid RFC 2047 Q escape')
      bytes.push(Number.parseInt(byte, 16))
      index += 2
      continue
    }
    const codePoint = character.charCodeAt(0)
    if (codePoint < 0x21 || codePoint > 0x7e) {
      throw new Error('invalid literal byte in RFC 2047 Q word')
    }
    bytes.push(codePoint)
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes))
}
