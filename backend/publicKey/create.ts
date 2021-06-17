import {
  generateCreationResponse,
  PublicKeyAlgorithm,
} from '../authenticator'
import type { CollectedClientData, CreateAuthenticatorOptions } from '../index'
import { checkUserVerification, filterCredentials } from '../util'

/**
 *
 * https://w3c.github.io/webauthn/#sctn-createCredential
 */
export async function create (
  createOptions: CreateAuthenticatorOptions,
  options: PublicKeyCredentialCreationOptions,
  signal?: AbortSignal,
): Promise<PublicKeyCredential | null> {
  // we dont trust these parameters from upstream
  delete options.timeout
  delete options.rp.id
  if (!await createOptions.hasCredential(options)) {
    return new Promise((resolve, reject) => {
      reject(new DOMException('NotSupportedError'))
    })
  }
  if (signal?.aborted) {
    return new Promise((resolve, reject) => {
      reject(new DOMException('AbortError'))
    })
  }
  const {
    rpID,
    ...normalizedOptions
  } = await createOptions.getNormalizedCreateOptions()
  const timeout = normalizedOptions.timeout as number
  const abortController = new AbortController()
  const expiredSignal = abortController.signal

  setTimeout(() => abortController.abort(), timeout)

  const credTypesAndPubKeyAlgorithms = [] as { type: string, alg: number }[]
  // If this array contains multiple elements, they are sorted by descending order of preference.
  //  We only support `ES256` algorithm
  if (Array.isArray(options.pubKeyCredParams) &&
    options.pubKeyCredParams.length > 0) {
    for (const param of options.pubKeyCredParams) {
      if (param.type !== 'public-key') {
        // we only allow 'public-key'
        // continue
      } else {
        credTypesAndPubKeyAlgorithms.push({ type: param.type, alg: param.alg })
      }
    }
    if (
      !credTypesAndPubKeyAlgorithms.find(
        alg => alg.alg === PublicKeyAlgorithm.ES256,
      )
    ) {
      throw new TypeError('Not Support Algorithms')
    }
  } else {
    // default algorithm
    credTypesAndPubKeyAlgorithms.push(
      { type: 'public-key', alg: PublicKeyAlgorithm.ES256 })
  }

  const collectedClientData: CollectedClientData = {
    type: 'webauthn.create',
    challenge: options.challenge,
    origin: rpID,
    crossOrigin: normalizedOptions.crossOrigin,
    tokenBinding: undefined,
  }
  // const collectedClientDataHash: string = await sha256(serializeCollectedClientData(collectedClientData))

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
      excludeCredentials = [],
      authenticatorSelection = {},
    } = options
    const {
      authenticatorAttachment = 'cross-platform',
      requireResidentKey = true,
      residentKey = 'required',
      userVerification = 'required',
    } = authenticatorSelection

    // In document, 'platform' means authenticator is bound to the client and is generally not removable.
    //  and 'cross-platform' means a device which may be used across different platform (NFC, USB)
    // However, in our library, 'cross-platform' means that the private key could sync with other platform using network, and vice versa.
    if (authenticatorAttachment === 'cross-platform') {
      let needResidentKey: boolean = requireResidentKey
      switch (residentKey) {
        case 'discouraged':
          throw new TypeError('Not support')
        case 'required':
        case 'preferred':
        default:
          needResidentKey = true
          break
      }
      const needUserVerification = checkUserVerification(userVerification)

      if (!needResidentKey) {
        throw new TypeError('must require resident key')
      }

      if (!needUserVerification) {
        // must allow user verification
        throw new TypeError('must user verification')
      }
      // tip: skip enterprise attestation

      let keys: CryptoKeyPair | null = null
      // see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/excludeCredentials
      //  this option used for the server to create new credentials for an existing user.
      if (Array.isArray(excludeCredentials) && excludeCredentials.length > 0) {
        const excludeCredentialDescriptorList: PublicKeyCredentialDescriptor[] =
          filterCredentials(excludeCredentials)

        keys = await createOptions.getKeyPairByKeyWrap(rpID,
          excludeCredentialDescriptorList.map(item => item.id))
        if (!keys) {
          throw new Error('')
        }
      }
      keys = await createOptions.getResidentKeyPair(rpID)
      const jwk = await crypto.subtle.exportKey('jwk', keys.privateKey)
      const signCount = await createOptions.getSignCount(jwk)
      return generateCreationResponse(
        keys,
        signCount,
        rpID,
        collectedClientData,
        credTypesAndPubKeyAlgorithms.map(alg => alg.alg),
        expiredSignal,
      ).then(response => {
        // we not guarantee this promise will resolve
        createOptions.incrementSignCount(jwk).catch(() => {/* ignore error */})
        return response
      })
    } else {
      // ignore 'platform'
      console.error('Not Support \'platform\'')
      return Promise.resolve().then(() => null)
    }
  }
}
