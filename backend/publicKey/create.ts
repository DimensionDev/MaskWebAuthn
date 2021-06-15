import { bufferSourceToBase64 } from '../util'
import {
  generateCreationResponse,
  hasCredential,
  PublicKeyAlgorithm,
} from '../authenticator'
import type { CreateAuthenticatorOptions } from '../index'

export type CollectedClientData = {
  type: 'webauthn.create'
  challenge: string
  origin: string
  crossOrigin: boolean
  tokenBinding: unknown
}

/**
 *
 * https://w3c.github.io/webauthn/#sctn-createCredential
 */
export async function create (
  createOptions: CreateAuthenticatorOptions,
  options: PublicKeyCredentialCreationOptions,
  signal?: AbortSignal,
): Promise<PublicKeyCredential | null> {
  if (hasCredential(options)) {
    return new Promise((resolve, reject) => {
      reject(new DOMException('NotSupportedError'))
    })
  }
  if (signal?.aborted) {
    return new Promise((resolve, reject) => {
      reject(new DOMException('AbortError'))
    })
  }
  const normalizedOptions = await createOptions.getNormalizedCreateOptions()
  const timeout = options.timeout as number
  const abortController = new AbortController()
  const expiredSignal = abortController.signal
  const rpID = normalizedOptions.rpID

  setTimeout(() => abortController.abort(), timeout)

  // get public key algorithm list
  const credTypesAndPubKeyAlgs = [] as { type: string, alg: number }[]
  // If this array contains multiple elements, they are sorted by descending order of preference.
  if (Array.isArray(options.pubKeyCredParams) &&
    options.pubKeyCredParams.length > 0) {
    for (const param of options.pubKeyCredParams) {
      if (param.type !== 'public-key') {
        // we only allow 'public-key'
        // continue
      } else {
        credTypesAndPubKeyAlgs.push({ type: param.type, alg: param.alg })
      }
    }
  } else {
    // default algs
    credTypesAndPubKeyAlgs.push(
      { type: 'public-key', alg: PublicKeyAlgorithm.ES256 })
    credTypesAndPubKeyAlgs.push(
      { type: 'public-key', alg: PublicKeyAlgorithm.RS256 })
  }

  const collectedClientData: CollectedClientData = {
    type: 'webauthn.create',
    challenge: bufferSourceToBase64(options.challenge),
    origin: normalizedOptions.rpID,
    crossOrigin: normalizedOptions.crossOrigin,  // todo: currentLy we not support crossOrigin
    tokenBinding: null,
  }

  if (signal?.aborted) {
    throw new DOMException('AbortError')
  }

  signal?.addEventListener('abort', function cleanup () {
    signal?.removeEventListener('abort', cleanup)
  })
  expiredSignal.addEventListener('abort', function cleanup () {
    expiredSignal.removeEventListener('abort', cleanup)
  })

  if (expiredSignal.aborted) {
    return Promise.resolve().then(() => null)
  } else {
    const {
      excludeCredentials,
      authenticatorSelection = {},
    } = options
    const {
      authenticatorAttachment = 'platform',
      requireResidentKey,
      residentKey,
      userVerification,
    } = authenticatorSelection

    // In document, 'platform' means authenticator is bound to the client and is generally not removable.
    //  and 'cross-platform' means a device which may be used across different platform (NFC, USB)
    // However, in our library, 'cross-platform' means that the private key could sync with other platform using network, and vice versa.
    if (authenticatorAttachment === 'cross-platform') {
      let requireResidentKey: boolean
      switch (residentKey) {
        case 'required':
        case 'discouraged':
        case 'preferred':
        default:
          requireResidentKey = true
          break
      }
      let needUserVerification: boolean
      // fixme: what is this?
      switch (userVerification) {
        case 'preferred':
        case 'required':
          // todo: check authenticator is capable
          needUserVerification = true
          break
        case 'discouraged':
        default:
          needUserVerification = false
          break
      }
      // tip: skip enterprise attestation

      const excludeCredentialDescriptorList = []
      let keys: CryptoKeyPair | null = null
      // see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/excludeCredentials
      //  this option used for the server to create new credentials for an existing user.
      //  todo: implement this part
      if (Array.isArray(options.excludeCredentials)) {
        for (const credential of options.excludeCredentials) {
          if (
            credential.transports &&
            Array.isArray(credential.transports) &&
            credential.transports.length > 0
          ) {
            // we dont use this
          } else if (credential.type === 'public-key') {
            // step 20.8
            excludeCredentialDescriptorList.push(credential)
          }
        }
        keys = await createOptions.getKeyPairByKeyWrap(rpID,
          excludeCredentialDescriptorList.map(item => item.id))
        if (!keys) {
          throw new Error('')
        }
      }
      keys = await createOptions.getResidentKeyPair(rpID)
      const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey)
      const signCount = await createOptions.getSignCount(jwk)
      return generateCreationResponse(
        keys,
        signCount,
        rpID,
        collectedClientData,
        credTypesAndPubKeyAlgs.map(alg => alg.alg),
        signal,
      ).then(response => {
        // we not guarantee this promise will resolve
        createOptions.incrementSignCount(jwk).catch(() => {/* ignore error */})
        return response
      })
    } else {
      // ignore 'platform'
      console.error('not support \'platform\'')
      return Promise.resolve().then(() => null)
    }
  }
}
