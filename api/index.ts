/// <reference path="./global.d.ts" />
import type {
    PublicKeyAuthenticatorProtocol,
    _FederatedAuthenticatorProtocol,
    _PasswordAuthenticatorProtocol,
} from '../types/interface'
export interface CreateCredentialsContainerOptions {
    publicKeyAuthenticator?: PublicKeyAuthenticatorProtocol
    federatedAuthenticator?: _FederatedAuthenticatorProtocol
    passwordAuthenticator?: _PasswordAuthenticatorProtocol
}
export function createCredentialsContainer(options: CreateCredentialsContainerOptions): CredentialsContainer {
    const { federatedAuthenticator, passwordAuthenticator, publicKeyAuthenticator } = options
    const supported: string[] = []
    if (passwordAuthenticator) supported.push('password')
    if (federatedAuthenticator) supported.push('federated')
    if (publicKeyAuthenticator) supported.push('publicKey')
    return {
        async create(opts = {}) {
            const fed = federatedAuthenticator ? opts.federated : void 0
            const password = passwordAuthenticator ? opts.password : void 0
            const pub = publicKeyAuthenticator ? opts.publicKey : void 0

            if (fed) {
                if (password || pub) throw NotSupported(supported)
                // use federatedAuthenticator
            } else if (password) {
                if (fed || pub) throw NotSupported(supported)
                // use passwordAuthenticator
            } else if (pub) {
                if (fed || password) throw NotSupported(supported)
                const { publicKeyAuthenticator } = options
                // todo: add security check function
                publicKeyAuthenticator!.create(pub, opts.signal)
                // use publicKeyAuthenticator
            }
            throw NotSupported(supported)
        },
        async get(opts = {}) {
            const fed = federatedAuthenticator ? opts.federated : void 0
            const password = passwordAuthenticator ? opts.password : void 0
            const pub = publicKeyAuthenticator ? opts.publicKey : void 0

            if (fed) {
                if (password || pub) throw NotSupported(supported)
                // use federatedAuthenticator
            } else if (password) {
                if (fed || pub) throw NotSupported(supported)
                // use passwordAuthenticator
            } else if (pub) {
                if (fed || password) throw NotSupported(supported)
                // use publicKeyAuthenticator
            }
            throw NotSupported(supported)
        },
        async store(_cred) {
            // Not supported by PublicKeyCredential. No need to implement.
            throw NotSupported(supported)
        },
        async preventSilentAccess() {
            throw new Error('Not implemented')
        },
    }
}
function NotSupported(supported: readonly string[]) {
    const list = new (Intl as any).ListFormat('en').format(supported.map((x) => `'${x}'`))
    return new DOMException(`Only exactly one of ${list} credential types are currently supported.`)
}
