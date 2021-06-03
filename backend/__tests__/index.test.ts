/* eslint-env jest */
import '../index'

test('public key credential creation options', () => {
  // refs: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
  const options: PublicKeyCredentialCreationOptions = {
    // Relying Party
    rp: {
      name: 'Example CORP',
      id: 'login.example.com',
    },
    challenge: new Uint8Array(26),
    // User
    user: {
      id: new Uint8Array(16),
      name: 'john.p.smith@example.com',
      displayName: 'John P. Smith',
    },
    // Requested format of new keypair
    pubKeyCredParams: [
      {
        type: 'public-key',
        alg: -7,
      }],
    // Timeout after 1 minute
    timeout: 60000,
    // Do not send the authenticator's origin attestation
    attestation: 'none',
    // Filter out authenticators which are bound to the device
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      requireResidentKey: true,
      userVerification: 'preferred',
    },
  }
})
