import { createCredentialsContainer } from '../api/index'
import { createPublicKeyAuthenticator } from '../backend/index'

const publicKeyAuthenticator = createPublicKeyAuthenticator({})
const credentialsContainer = createCredentialsContainer(
  { publicKeyAuthenticator })

Object.assign(globalThis, { cred: credentialsContainer })
console.log('The mock implementation has been installed on window.cred')

export function loginWithMask () {
  console.log('login with mask')
}
