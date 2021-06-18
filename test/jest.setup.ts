import { Crypto } from '@peculiar/webcrypto'

const crypto = new Crypto()

Object.defineProperty(globalThis, 'crypto', {
  get (): Crypto {
    return crypto
  },
  set (v: any) {
    // ignore
  }
})
