import { Buffer } from 'buffer'

const keyToCOSEKey = (key: keyof JsonWebKey): [label: number, allowedType: Type[]] => {
    switch (key) {
        case 'kty':
            return [1, [MajorType.UTF8String, MajorType.PosInt, MajorType.NegInt]]
        case 'alg':
            return [3, [MajorType.ByteString]]
        case 'key_ops':
            return [4, [MajorType.UTF8String, MajorType.PosInt, MajorType.NegInt]]
        case 'crv':
            return [-1, [MajorType.UTF8String, MajorType.PosInt, MajorType.NegInt]]
        case 'x':
            return [-2, [MajorType.ByteString]]
        case 'y':
            return [-3, [MajorType.ByteString, SimpleType.True, SimpleType.False]]
        case 'd':
            return [-4, [MajorType.ByteString]]
        default:
            throw new TypeError()
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

export type Type = MajorType | SimpleType

export const isMajorType = (v: Type): v is MajorType => v >= 0 && v <= 7
export const isSimpleType = (v: Type): v is SimpleType => v >= SimpleType.False && v <= SimpleType.Undefined

type WithType = (type: MajorType, payload: number) => number
type WithTypeWrapper = (payload: number) => ReturnType<WithType>

const withType: WithType = (type: MajorType, payload: number): number => (type << 5) + payload
const withNegInt: WithTypeWrapper = (payload: number) => withType(MajorType.NegInt, payload)
const withPosInt: WithTypeWrapper = (payload: number) => withType(MajorType.PosInt, payload)
const withUtf8: WithTypeWrapper = (payload: number) => withType(MajorType.UTF8String, payload)
const withBStr: WithTypeWrapper = (payload) => withType(MajorType.ByteString, payload)

function parseNumber(number: number, withType: WithTypeWrapper): ArrayBuffer {
    let startBuffer: Buffer
    let endBuffer = Buffer.alloc(0)
    if (number < 0x18) {
        startBuffer = Buffer.from([withType(number)])
    } else {
        if (number <= INT8_MAX) {
            startBuffer = Buffer.from([withType(0x18)])
        } else if (number <= INT16_MAX) {
            startBuffer = Buffer.from([withType(0x19)])
        } else if (number <= INT32_MAX) {
            startBuffer = Buffer.from([withType(0x1a)])
        } else {
            startBuffer = Buffer.from([withType(0x1b)])
        }
        endBuffer = Buffer.from(toByteArray(number))
    }
    return Buffer.concat([startBuffer, endBuffer])
    function toByteArray(x: number, padding?: number): ArrayBuffer {
        const LogTable = [1, 1, 2, 4, 4] as const
        const array = [] as Uint8Array[]
        if (x > INT32_MAX) {
            // javascript cannot handle bit operators with number larger than int32
            const y = Math.floor(x / 2 ** 32) // handle the high level
            array.unshift(Buffer.from(toByteArray(y)))
            while (array.length < 4) {
                array.unshift(Buffer.from([0]))
            }
            return Buffer.concat([...array, Buffer.from(toByteArray(x & INT32_MAX, 4))])
        } else {
            while (x > 0) {
                const byte = x & 0xff /* INT8_MAX */
                array.unshift(Buffer.from([byte]))
                x >>>= 8
            }
            while (array.length < (padding || LogTable[array.length])) {
                array.unshift(Buffer.from([0]))
            }
        }
        return Buffer.concat(array)
    }
}

export const Number = (number: number): ArrayBuffer => {
    if (number >= 0 || number === -0) {
        return parseNumber(number, withPosInt)
    } else {
        return parseNumber(-number - 1, withNegInt)
    }
}

export const UTF8String = (string: string): ArrayBuffer => {
    const stringBuffer = Buffer.from(string, 'utf-8')
    const startBuffer = Buffer.from(parseNumber(stringBuffer.byteLength, withUtf8))
    return Buffer.concat([startBuffer, stringBuffer])
}

export const ByteString = (string: string): ArrayBuffer => {
    const stringBuffer = Buffer.from(string, 'hex')
    const startBuffer = Buffer.from(parseNumber(stringBuffer.byteLength, withBStr))
    return Buffer.concat([startBuffer, stringBuffer])
}

declare global {
    interface ObjectConstructor {
        getOwnPropertyNames<T extends any = any>(value: T): (keyof T)[]
    }
}

export const MajorTypeMap = {
    [MajorType.PosInt]: Number,
    [MajorType.NegInt]: Number,
    [MajorType.UTF8String]: UTF8String,
    [MajorType.ByteString]: ByteString,
} as Record<MajorType, <T extends any = any>(value: T) => ArrayBuffer>

export const SimpleTypeMap = {
    [SimpleType.True]: (value: any) => value === true,
    [SimpleType.False]: (value: any) => value === false,
    [SimpleType.Undefined]: (value: any) => value === undefined,
    [SimpleType.NULL]: (value: any) => value === null,
} as Record<SimpleType, <T extends any = any>(value: any) => value is T>

function parseType(types: Type[], value: any): ArrayBuffer {
    for (let type of types) {
        if (isMajorType(type)) {
            const parsed = matchMajorType(type, value)
            if (parsed != null) {
                return parsed
            }
        } else if (isSimpleType(type)) {
            const parsed = matchSimpleType(type, value)
            if (parsed != null) {
                return parsed
            }
        } else {
            throw new TypeError('unreachable')
        }
    }
    throw new TypeError('incorrect type')
    function matchMajorType(type: MajorType, value: any): undefined | ArrayBuffer {
        const callee = MajorTypeMap[type]
        if (callee) {
            return callee(value)
        } else {
            return undefined
        }
    }
    function matchSimpleType(type: SimpleType, value: boolean | undefined | null): undefined | ArrayBuffer {
        if (SimpleTypeMap[type](value)) {
            return Buffer.from([type])
        } else {
            return
        }
    }
}

// todo: refactor to parseObject
export function parseJsonWebKey(jwk: JsonWebKey): ArrayBuffer {
    const result: Buffer[] = []
    // todo: remove INF_MAP_START
    result.push(Buffer.from([INF_MAP_START]))
    for (let key of Object.getOwnPropertyNames(jwk)) {
        const [label, types] = keyToCOSEKey(key)
        pushKeyValue(Buffer.from(Number(label)), Buffer.from(parseType(types, jwk[key])))
    }

    // todo: remove INF_MAP_START
    result.push(Buffer.from([BREAK]))

    return Buffer.concat(result)
    function pushKeyValue(key: Buffer, value: Buffer) {
        result.push(key)
        result.push(value)
    }
}
