export interface PublicKeyAuthenticatorProtocol {
  create(options: PublicKeyCredentialCreationOptions, signal?: AbortSignal): Promise<Credential | null>
  get(options: PublicKeyCredentialRequestOptions, signal?: AbortSignal): Promise<Credential | null>
}
export interface _FederatedAuthenticatorProtocol {}
export interface _PasswordAuthenticatorProtocol {}
