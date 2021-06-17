import { createCredentialsContainer } from '../api'
import {
  createPublicKeyAuthenticator,
  NormalizedCreateOptions
} from '../backend'

// todo
const publicKeyAuthenticator = createPublicKeyAuthenticator({
  hasCredential (options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions): Promise<boolean> {
    throw new Error()
  },
  hasKeyPairKeyWrap (credentialID: BufferSource[]): Promise<boolean> {
    throw new Error()
  },
  incrementSignCount (key: JsonWebKey): Promise<void> {
    throw new Error()
  },
  getSignCount (key: JsonWebKey): Promise<number> {
    throw new Error()
  },
  getKeyPairByKeyWrap (rpID: string, credentialID: ArrayBuffer[]): Promise<CryptoKeyPair> {
    throw new Error()
  },
  getResidentKeyPair (rpID: string): Promise<CryptoKeyPair> {
    throw new Error()
  },
  getNormalizedCreateOptions (): Promise<NormalizedCreateOptions> {
    throw new Error()
  }
})

const credentialsContainer = createCredentialsContainer(
  { publicKeyAuthenticator })

Object.assign(globalThis, { cred: credentialsContainer })
console.log('The mock implementation has been installed on window.cred')

export function loginWithMask () {
  // todo
  credentialsContainer.create({})
}
