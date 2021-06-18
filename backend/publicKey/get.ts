import type { CreateAuthenticatorOptions } from '../index'
import { checkUserVerification, filterCredentials } from '../util'
import { generateCreationResponse } from '../authenticator'
import type { CollectedClientData } from '../../types/interface'

export async function get (
  createOptions: CreateAuthenticatorOptions,
  options: PublicKeyCredentialRequestOptions,
  signal?: AbortSignal
) {
  // we dont trust these parameters from upstream
  delete options.timeout
  delete options.rpId
  if (!await createOptions.hasCredential(options)) {
    return Promise.reject(new DOMException('NotSupportedError'))
  } else if (signal?.aborted) {
    return Promise.reject(new DOMException('AbortError'))
  }
  const normalizedOptions = await createOptions.getNormalizedCreateOptions()
  const timeout = normalizedOptions.timeout as number
  const abortController = new AbortController()
  const expiredSignal = abortController.signal
  const rpID = normalizedOptions.rpID

  setTimeout(() => abortController.abort(), timeout)

  const collectedClientData: CollectedClientData = {
    type: 'webauthn.get',
    challenge: normalizedOptions.challenge,
    origin: normalizedOptions.rpID,
    crossOrigin: normalizedOptions.crossOrigin,
    tokenBinding: null
  }
  const { userVerification, allowCredentials } = options
  // const collectedClientDataHash: string = await sha256(serializeCollectedClientData(collectedClientData))

  const needUserVerification = checkUserVerification(
    userVerification || 'preferred'
  )
  if (!needUserVerification) {
    // must allow user verification
    throw new TypeError('must user verification')
  }

  let keys: CryptoKeyPair | null = null
  let credentialID: ArrayBuffer | null = null
  // see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/excludeCredentials
  //  this option used for the server to create new credentials for an existing user.
  if (Array.isArray(allowCredentials)) {
    const excludeCredentialDescriptorList: PublicKeyCredentialDescriptor[] =
      filterCredentials(allowCredentials)
    ;[keys, credentialID] = await createOptions.getKeyPairByKeyWrap(rpID,
      excludeCredentialDescriptorList.map(item => item.id))
    if (!keys) {
      throw new Error('')
    }
  }
  [keys, credentialID] = await createOptions.getResidentKeyPair(rpID)
  const signCount = await createOptions.getSignCount(keys.privateKey)
  return generateCreationResponse(
    credentialID,
    keys,
    signCount,
    rpID,
    collectedClientData,
    [],
    expiredSignal
  ).then(response => {
    // we not guarantee this promise will resolve
    createOptions.incrementSignCount(keys!.privateKey).catch(() => { /* ignore error */ })
    return response
  })
}
