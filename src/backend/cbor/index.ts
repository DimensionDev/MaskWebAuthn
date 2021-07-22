import { concatenate, stringToArrayBuffer } from '../util'
import { Alg, CoseKey, Crv, Kty } from '../../../types/interface'

declare global {
    interface ObjectConstructor {
        getOwnPropertyNames<T extends any = any>(value: T): (keyof T)[]
    }
}

enum kty {
    OKP = 1,
    EC2 = 2,
    Symmetric = 4,
    Reserved = 0,
}

const INT8_MAX = 2 ** 8 - 1
const INT16_MAX = 2 ** 16 - 1
const INT32_MAX = 2 ** 32 - 1
const INF_MAP_START = 0xbf
const BREAK = 0xff

export enum MajorType {
    PosInt = 0b000, // 0
    NegInt = 0b001, // 1
    ByteString = 0b010, // 2
    UTF8String = 0b011, // 3
    Array = 0b100, // 4
    Map = 0b101, // 5
    Tag = 0b110, // 6
    Float = 0b111, // 7
}

export enum SimpleType {
    False = 0xf4, // 20
    True = 0xf5, // 21
    NULL = 0xf6, //22
    Undefined = 0xf7, //23
}

export enum LengthType {
    UINT8 = 0x18,
    UINT16 = 0x19,
    UINT32 = 0x1a,
    UINT64 = 0x1b,
    INF = 0x1f,
}

export type Type = MajorType | SimpleType

export const isMajorType = (v: Type): v is MajorType => v >= 0 && v <= 7
export const isSimpleType = (v: Type): v is SimpleType => v >= SimpleType.False && v <= SimpleType.Undefined

type WithType = (type: MajorType, payload: number) => number
type WithTypeWrapper = (payload: number | LengthType) => ReturnType<WithType>

const withType: WithType = (type: MajorType, payload: number): number => (type << 5) + payload
const withNegInt: WithTypeWrapper = (payload) => withType(MajorType.NegInt, payload)
const withPosInt: WithTypeWrapper = (payload) => withType(MajorType.PosInt, payload)
const withUtf8: WithTypeWrapper = (payload) => withType(MajorType.UTF8String, payload)
const withBStr: WithTypeWrapper = (payload) => withType(MajorType.ByteString, payload)
const withSet: WithTypeWrapper = (payload) => withType(MajorType.Array, payload)
const withMap: WithTypeWrapper = (payload) => withType(MajorType.Map, payload)

function parseNumber(number: number, withType: WithTypeWrapper): ArrayBuffer {
    let startBuffer: Uint8Array
    let endBuffer = new Uint8Array(0)
    if (number < 0x18) {
        startBuffer = new Uint8Array([withType(number)])
    } else {
        if (number <= INT8_MAX) {
            startBuffer = new Uint8Array([withType(0x18)])
        } else if (number <= INT16_MAX) {
            startBuffer = new Uint8Array([withType(0x19)])
        } else if (number <= INT32_MAX) {
            startBuffer = new Uint8Array([withType(0x1a)])
        } else {
            startBuffer = new Uint8Array([withType(0x1b)])
        }
        endBuffer = new Uint8Array(toByteArray(number))
    }
    return concatenate(startBuffer, endBuffer)
    function toByteArray(x: number, padding?: number): ArrayBuffer {
        const LogTable = [-1, 1, 2, 4, 4] as const
        const array = [] as Uint8Array[]
        if (x > INT32_MAX) {
            // javascript cannot handle bit operators with number larger than int32
            const y = Math.floor(x / 2 ** 32) // handle the high level
            array.unshift(new Uint8Array(toByteArray(y)))
            while (array.length < 4) {
                array.unshift(new Uint8Array([0]))
            }
            return concatenate(...array, toByteArray((x & (2 ** 31 - 1)) + (x & (1 << 31) ? 2 ** 31 : 0), 4))
        } else {
            while (x > 0) {
                const byte = x & 0xff /* INT8_MAX */
                array.unshift(new Uint8Array([byte]))
                x >>>= 8
            }
            while (array.length < (padding || LogTable[array.length])) {
                array.unshift(new Uint8Array([0]))
            }
        }
        return concatenate(...array)
    }
}

export type Hooks = {
    // todo
}

export type EncodeOptions = {
    lengthPrefer?: LengthType
    hooks?: Hooks
}

export type Encoder = (data?: any, options?: EncodeOptions) => ArrayBuffer
// Simple Value encode, no need options
export const Undefined: Encoder = (): ArrayBuffer => new Uint8Array([SimpleType.Undefined])
export const Null: Encoder = (): ArrayBuffer => new Uint8Array([SimpleType.NULL])
export const Boolean: Encoder = (bool: boolean): ArrayBuffer =>
    new Uint8Array([bool ? SimpleType.True : SimpleType.False])
// Major Type encode
export const Number: Encoder = (number: number, options?: EncodeOptions): ArrayBuffer => {
    if (number >= 0 || number === -0) {
        return parseNumber(number, withPosInt)
    } else {
        return parseNumber(-number - 1, withNegInt)
    }
}

export const UTF8String: Encoder = (string: string, options = {}): ArrayBuffer => {
    const stringBuffer = stringToArrayBuffer(string, 'utf-8')
    const startBuffer = new Uint8Array(parseNumber(stringBuffer.byteLength, withUtf8))
    return concatenate(startBuffer, stringBuffer)
}

export const ByteString: Encoder = (string: string, options = {}): ArrayBuffer => {
    const stringBuffer = stringToArrayBuffer(string, 'hex')
    const startBuffer = new Uint8Array(parseNumber(stringBuffer.byteLength, withBStr))
    return concatenate(startBuffer, stringBuffer)
}

export const ObjectLike: Encoder = (object: object, options = {}): ArrayBuffer => {
    if (Array.isArray(object)) {
        return handleArray(object.entries())
    } else if (object instanceof Map) {
        return handleObjectLike(object.entries())
    } else if (object instanceof Set) {
        return handleArray(object.entries())
    } else {
        return handleObjectLike(Object.entries(object)[Symbol.iterator]())
    } // end
    function handleArray(iter: IterableIterator<[value: unknown, value: unknown]>): ArrayBuffer {
        let length = 0
        const followingBuffers: Uint8Array[] = []
        for (const [value] of iter) {
            length++
            followingBuffers.push(new Uint8Array(encode(value)))
        }
        const startBuffer = new Uint8Array(parseNumber(length, withSet))
        return concatenate(startBuffer, ...followingBuffers)
    }
    function handleObjectLike(iter: IterableIterator<[key: unknown, value: unknown]>): ArrayBuffer {
        let length = 0
        const followingBuffers: Uint8Array[] = []
        for (const [key, value] of iter) {
            length++
            followingBuffers.push(new Uint8Array(encode(key)))
            followingBuffers.push(new Uint8Array(encode(value)))
        }
        const startBuffer = new Uint8Array(parseNumber(length, withMap))
        return concatenate(startBuffer, ...followingBuffers)
    }
}

export function encode<T extends any = any>(data: T, options: EncodeOptions = {}): ArrayBuffer {
    if (data == null) {
        if (data === undefined) {
            return Undefined()
        } else {
            return Null()
        }
    } else {
        switch (typeof data) {
            case 'number': {
                return Number(data as number, options)
            }
            case 'boolean': {
                return Boolean(data as boolean, options)
            }
            case 'object': {
                return ObjectLike(data as object, options)
            }
            case 'string': {
                return UTF8String(data as string, options)
            }
            case 'function':
            case 'bigint':
            case 'symbol': {
                throw new TypeError('not support')
            }
            default:
                throw new Error('unreachable')
        }
    }
}

// if second element exists, that means the valueMap for the value
const keyToCoseMap = {
    kty: Kty,
    crv: Crv,
    alg: Alg,
} as Record<string, Record<string, any> | undefined>

export function parseJsonWebKey(jwk: JsonWebKey): ArrayBuffer {
    const array = [] as Uint8Array[]
    let length = 0
    for (let key of Object.getOwnPropertyNames(jwk)) {
        if (key in CoseKey) {
            const newKey = CoseKey[key as keyof typeof CoseKey]
            const valueMap = keyToCoseMap[key]
            const newValue = valueMap ? valueMap[jwk[key] as keyof typeof valueMap] : jwk[key]
            if (newKey == null || newValue == null) {
                throw new TypeError('not found key')
            }
            array.push(new Uint8Array(encode(newKey)))
            array.push(new Uint8Array(encode(newValue)))
            length++
        }
    }
    // add length
    array.unshift(new Uint8Array(parseNumber(length, withMap)))
    return concatenate(...array)
}
