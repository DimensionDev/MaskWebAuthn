import { bufferSourceToBase64, isRegistrableDomain } from '../util'
import auth from '../authenticator'

export type CollectedClientData = {
  type: string
  challenge: string
  origin: string
  crossOrigin: boolean
}

export function create (
  privateKey: JsonWebKey,
  publicKey: JsonWebKey,
  options: PublicKeyCredentialCreationOptions,
  signal: AbortSignal): Promise<PublicKeyCredential | null> {
  let settings = document
  let sameOriginWithAncestors = isSecureContext
  if (!sameOriginWithAncestors) {
    throw new DOMException()
  }
  if (auth.findCredential(options)) {
    return new Promise((resolve, reject) => {
      reject(new DOMException('NotSupportedError'))
    })
  }
  if (signal.aborted) {
    return new Promise((resolve, reject) => {
      reject(new DOMException('AbortError'))
    })
  }
  return new Promise<PublicKeyCredential | null>((resolve, reject) => {
    // calling createSync
    const publicKeyCredentialOrError = createSync(
      privateKey,
      publicKey,
      origin,
      options,
      sameOriginWithAncestors,
      signal
    )
    if (publicKeyCredentialOrError instanceof Error) {
      reject(publicKeyCredentialOrError as Error)
    } else {
      resolve(publicKeyCredentialOrError as PublicKeyCredential | null)
    }
  })
}

function createSync (
  privateKey: JsonWebKey,
  publicKey: JsonWebKey,
  origin: string,
  options: PublicKeyCredentialCreationOptions,
  sameOriginWithAncestors: boolean,
  signal: AbortSignal,
): PublicKeyCredential | Error | null {
  const timeout = Math.min(60000 /* 6 seconds */, options.timeout || 0)

  const hasExpired = () => expired
  let expired = false
  setTimeout(() => { expired = true }, timeout)

  const idLength = options.user.id.byteLength
  if (idLength < 1 || idLength > 64) {
    throw new TypeError()
  }
  // fixme: incorrect implementation
  const callerOrigin = window.origin
  const effectiveDomain = document.domain
  if (options.rp.id) {
    if (!isRegistrableDomain(options.rp.id, effectiveDomain)) {
      return new DOMException('SecurityError')
    }
  } else {
    options.rp.id = effectiveDomain
  }

  let credTypesAndPubKeyAlgs = [] as { type: string, alg: number }[]
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
  const collectedUserData = {

  }
  const collectedClientData: CollectedClientData = {
    type: 'webauthn.create',
    challenge: bufferSourceToBase64(options.challenge),
    origin: callerOrigin,
    crossOrigin: false  // todo: currentLy we not support crossOrigin
  }

  if (signal.aborted) {
    return new DOMException('AbortError')
  }
  signal.addEventListener('abort', cleanup)

  if (hasExpired()) {
    return null
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
      const rpID = options.rp.id
      auth.derivePublicKey(privateKey, publicKey, rpID, {}, collectedClientData)
      return null
    } else {
      // ignore 'cross-platform'
      console.error('not support \'cross-platform\'')
      return null
    }
  }

  function cleanup () {
    // remove this from abort signal
    signal.removeEventListener('abort', cleanup)
  }
}
