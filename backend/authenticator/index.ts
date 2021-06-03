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

export interface AuthenticatorResponseData {
  credentialID: string
  publicKey: JsonWebKey
}

// todo
export type AuthenticatorTask = PublicKeyCredentialCreationOptions

const kIssuedRequests = Symbol('issuedRequests')
const kRelevantCredentials = Symbol('relevantCredentials')

const supportSet = new Set<number>([-7])

let resolve: (value: IDBPDatabase<AuthenticatorDB>) => void, reject: (reason?: any) => void
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
    const _ = this.db
  }

  public async derivePublicKey (
    privateKey: JsonWebKey,
    publicKey: JsonWebKey,
    rpID: string,
    userInfo: any,
    clientData: CollectedClientData
  ): Promise<AuthenticatorResponseData> {
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
    t?.add({
      domain: rpID,
      challenge: clientData.challenge,
      publicKey: jwk
    })

    return {
      credentialID: '',
      publicKey: jwk
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
