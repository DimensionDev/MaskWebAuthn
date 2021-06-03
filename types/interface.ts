export interface PublicKeyAuthenticatorProtocol {
  create(options: PublicKeyCredentialCreationOptions, signal: AbortSignal): void
  signal: AbortSignal,
  abort(): void
}
export interface _FederatedAuthenticatorProtocol {}
export interface _PasswordAuthenticatorProtocol {}
