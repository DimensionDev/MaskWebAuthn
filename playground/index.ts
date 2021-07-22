import { createCredentialsContainer } from '../src/api'
import { createPublicKeyAuthenticator, NormalizedCreateOptions } from '../src/backend'

const publicKeyCredentialOptionsMap = new Set<any>()
const keyCounter = new WeakMap<CryptoKey, number>()
const keys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'encrypt',
    'decrypt',
    'sign',
    'verify',
])
const credentialID = new Uint8Array(16).fill(0x11).buffer
const challenge = new Uint8Array(16).map((_, index) => index % 8)

const publicKeyAuthenticator = createPublicKeyAuthenticator({
    hasCredential(rpID: string, credentialID?: ArrayBuffer | null): Promise<boolean> {
        return new Promise<boolean>((resolve) => {
            if (
                publicKeyCredentialOptionsMap.has({
                    rpID,
                })
            ) {
                resolve(true)
            } else {
                publicKeyCredentialOptionsMap.add({
                    rpID,
                })
                resolve(false)
            }
        })
    },
    incrementSignCount(key: CryptoKey): Promise<void> {
        keyCounter.set(key, (keyCounter.get(key) || 0) + 2)
        return Promise.resolve()
    },
    getSignCount(key: CryptoKey): Promise<number> {
        return new Promise((resolve) => {
            const count = keyCounter.get(key)
            if (!count) {
                throw new Error('Not Found')
            }
            resolve(count)
        })
    },
    getKeyPairByKeyWrap(rpID: string, credentialIDs: ArrayBuffer[]): Promise<[CryptoKeyPair, ArrayBuffer]> {
        return Promise.resolve([keys, credentialID])
    },
    getResidentKeyPair(rpID: string): Promise<[CryptoKeyPair, ArrayBuffer]> {
        return Promise.resolve([keys, credentialID])
    },
    async getNormalizedCreateOptions(): Promise<NormalizedCreateOptions> {
        const k = await keys
        return Promise.resolve().then(() => ({
            keys: k,
            timeout: 1000 * 6,
            rpID: 'https://localhost:8080',
            challenge: challenge,
            crossOrigin: false,
        }))
    },
})

const credentialsContainer = createCredentialsContainer({ publicKeyAuthenticator })

Object.assign(globalThis, { cred: credentialsContainer })
console.log('The mock implementation has been installed on window.cred')

export function loginWithMask() {
    // todo
    credentialsContainer.create({})
}
