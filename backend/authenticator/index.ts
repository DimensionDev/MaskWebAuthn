import {
  bufferSourceToBase64,
  getKeyParameter,
  JsonWebKeyToCryptoKey,
} from '../util'
import {
  DBSchema,
  openDB,
  IDBPDatabase,
} from 'idb/with-async-ittr-cjs'
import type { CollectedClientData } from '../publicKey/create'
import { encode } from 'cbor-web'

export type WebAuth = {
  domain: string  // unique key
  challenge: string // received from third-party server
  publicKey: JsonWebKey // would respond to the third-party server
}

export interface AuthenticatorDB extends DBSchema {
  webAuths: {
    key: string,
    value: WebAuth
  }
}

// todo
export type AuthenticatorTask = PublicKeyCredentialCreationOptions

const kIssuedRequests = Symbol('issuedRequests')
const kRelevantCredentials = Symbol('relevantCredentials')

const supportSet = new Set<number>([-7])

let resolve: (value: IDBPDatabase<AuthenticatorDB>) => void,
  reject: (reason?: any) => void
const dbPromise: Promise<IDBPDatabase<AuthenticatorDB>> = new Promise(
  (_resolve, _reject) => {
    resolve = _resolve
    reject = _reject
  })
let realDB: IDBPDatabase<AuthenticatorDB> | null = null

// todo: use IndexedDB
class Authenticator {
  static VERSION = 1 as const

  private [kIssuedRequests]: AuthenticatorTask[] = []
  private [kRelevantCredentials] = new Map<string, boolean>()

  private get db (): Promise<IDBPDatabase<AuthenticatorDB> | null> {
    if (realDB == null) {
      openDB<AuthenticatorDB>('maskbook-login', Authenticator.VERSION, {
        // todo: add update handler
      }).then(db => {
        db.addEventListener('close', () => { realDB = null })
        db.addEventListener('error', () => { realDB = null })
        realDB = db
        resolve(realDB)
      })
    }
    return dbPromise
  }

  constructor () {
    // connect database as soon as possible
    const _ = this.db
  }

  public async derivePublicKey (
    // maskbook provided
    privateKey: JsonWebKey,
    publicKey: JsonWebKey,
    // user provided
    rpID: string,
    userInfo: any,
    clientData: CollectedClientData,
    // other options
    signal?: AbortSignal,
  ): Promise<PublicKeyCredential> {
    const aes = 'AES-GCM'
    const length = 256
    // todo
    const key = await crypto.subtle.deriveKey({
        name: 'ECDH',
        public: await JsonWebKeyToCryptoKey(publicKey,
          ...getKeyParameter('ecdh')),
      },
      await JsonWebKeyToCryptoKey(privateKey, ...getKeyParameter('ecdh')),
      { name: aes, length },
      true,
      ['encrypt', 'decrypt', 'sign', 'verify'])
    const t = (await this.db)?.transaction('webAuths', 'readwrite').
      objectStore('webAuths')
    const jwk = await crypto.subtle.exportKey('jwt', key) as JsonWebKey
    if (signal?.aborted) {
      throw new DOMException('AbortError')
    }

    t?.add({
      domain: rpID,
      challenge: clientData.challenge,
      publicKey: jwk,
    })

    // id includes username and email, then it will save to the local database as the unique key
    const id = `${userInfo.username}+${userInfo.email}`
    const rawId = new TextEncoder().encode(id)
    const base64ID = bufferSourceToBase64(rawId)

    const attestationObject = encode({
      fmt: '',
      attStmt: {},
      antData: new Uint8Array()
    }) as Uint8Array

    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
      challenge: clientData.challenge,  // relying party will check the challenge
      origin: clientData.origin,  // 'https://xxx.xx'
      type: clientData.type // 'webauthn.create'
    }))

    return {
      id: base64ID,
      rawId,
      response: {
        clientDataJSON,
        attestationObject
      } as AuthenticatorAttestationResponse,
      type: 'public-key',
      getClientExtensionResults (): AuthenticationExtensionsClientOutputs {
        throw new Error('not supported')
      },
    }
  }

  public findCredential (credential: PublicKeyCredentialCreationOptions): boolean {
    const {
      rp,
      challenge,
      user,
    } = credential
    const base = bufferSourceToBase64(challenge)
    const json = JSON.stringify({ challenge: base, rp, user })
    if (this[kRelevantCredentials].has(json)) {
      return true
    } else {
      this[kRelevantCredentials].set(json, true)
      return false
    }
  }

  public support = (alg: number) => supportSet.has(alg)
}

export default new Authenticator()
