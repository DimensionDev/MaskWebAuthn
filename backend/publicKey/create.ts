import { bufferSourceToBase64, isRegistrableDomain } from '../util'
import auth from '../authenticator'

export type CollectedUserData = {
  username: string
  id: string
}

export type CollectedClientData = {
  type: string
  challenge: string
  origin: string
  crossOrigin: boolean
}

/**
 * @this SecurityContext
 */
export async function create (
  privateKey: JsonWebKey,
  publicKey: JsonWebKey,
  options: PublicKeyCredentialCreationOptions,
  signal?: AbortSignal): Promise<PublicKeyCredential | null> {
  if (auth.findCredential(options)) {
    return new Promise((resolve, reject) => {
      reject(new DOMException('NotSupportedError'))
    })
  }
  if (signal?.aborted) {
    return new Promise((resolve, reject) => {
      reject(new DOMException('AbortError'))
    })
  }
  return createImpl(
    privateKey,
    publicKey,
    options,
    signal,
  )
}

/**
 * @this SecurityContext
 */
function createImpl (
  privateKey: JsonWebKey,
  publicKey: JsonWebKey,
  options: PublicKeyCredentialCreationOptions,
  signal?: AbortSignal,
): Promise<PublicKeyCredential | null> {
  const timeout = Math.min(60000 /* 6 seconds */, options.timeout || 0)
  const abortController = new AbortController()
  const expiredSignal = abortController.signal
  let rpID: string = ''

  setTimeout(() => abortController.abort(), timeout)

  const idLength = options.user.id.byteLength
  if (idLength < 1 || idLength > 64) {
    const error = new TypeError()
    error.message = 'Incorrect length of `options.user.id`'
  }
  // fixme: incorrect implementation
  const callerOrigin = window.origin
  const effectiveDomain = document.domain // current domain
  if (options.rp.id) {
    if (!isRegistrableDomain(options.rp.id, effectiveDomain)) {
      throw new DOMException('SecurityError')
    } else {
      rpID = options.rp.id
    }
  } else {
    rpID = effectiveDomain
  }

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
    credTypesAndPubKeyAlgs.push({ type: 'public-key', alg: -7 })  // ES256
    credTypesAndPubKeyAlgs.push({ type: 'public-key', alg: -257 })  // RS256
  }

  const collectedUserData: CollectedUserData = {
    id: bufferSourceToBase64(options.user.id),
    username: options.user.name,
  }
  const collectedClientData: CollectedClientData = {
    type: 'webauthn.create',
    challenge: bufferSourceToBase64(options.challenge),
    origin: callerOrigin,
    crossOrigin: false,  // todo: currentLy we not support crossOrigin
  }

  if (signal?.aborted) {
    throw new DOMException('AbortError')
  }

  signal?.addEventListener('abort', function cleanup() {
    signal?.removeEventListener('abort', cleanup)
  })
  expiredSignal.addEventListener('abort', function cleanup() {
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
    // todo: currently we only support platform because we have not cloud server yet.
    if (authenticatorAttachment === 'platform') {
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
      // see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/excludeCredentials
      //  this option used for the server to create new credentials for an existing user.
      //  todo: implement this part
      for (const credential of options.excludeCredentials || []) {
        if (
          credential.transports &&
          Array.isArray(credential.transports) &&
          credential.transports.length > 0
        ) {
          // we dont use this
        } else {
          excludeCredentialDescriptorList.push(credential)
          // todo: step 20.8
        }
      }
      // todo: generate the key
      return auth.derivePublicKey(
        privateKey,
        publicKey,
        rpID,
        collectedUserData,
        collectedClientData,
        signal,
      )
    } else {
      // ignore 'cross-platform'
      console.error('not support \'cross-platform\'')
      return Promise.resolve().then(() => null)
    }
  }
}
