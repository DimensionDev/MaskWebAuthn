export interface PublicKeyAuthenticatorProtocol {
  create(options: PublicKeyCredentialCreationOptions, signal?: AbortSignal): void
}
export interface _FederatedAuthenticatorProtocol {}
export interface _PasswordAuthenticatorProtocol {}
