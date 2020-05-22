import argon2 from 'argon2-browser'

export const hasNativeCryptoSupport = () =>
  Boolean(
    window.crypto && window.crypto.getRandomValues && window.crypto.subtle
  )

const RAW = 'raw'
const SHA512 = 'SHA-512'

const AES_GCM = 'AES-GCM'
const AES_KEY_SIZE = 256
const AES_TAG_LENGTH = 96

export const firstReadableChar = ' '.charCodeAt(0)
export const lastReadableChar = '~'.charCodeAt(0)
const readableCharSize = lastReadableChar + 1 - firstReadableChar

export const convertByteToReadableChar = (v) =>
  String.fromCharCode((v % readableCharSize) + firstReadableChar)

export const generateRandomString = (size = 32) => {
  let s = ''
  window.crypto
    .getRandomValues(new Uint8Array(size))
    .forEach((v) => (s += convertByteToReadableChar(v)))
  return s
}

const getDerivationParams = (p = {}) => {
  const {
    type = argon2.ArgonType.Argon2id,
    time = 100, // default number of iterations
    mem = 1024, // default used memory, in KiB
    parallelism = 1, // default desired parallelism (only for PNaCl)
    salt = generateRandomString(32), // generate a 32 chars random salt if not defined
  } = p
  return {
    type,
    time,
    mem,
    parallelism,
    salt,
  }
}

const derivateKey = async (password, inputParams) => {
  const params = getDerivationParams(inputParams)
  return (
    argon2
      .hash({
        pass: password,
        hashLen: 32, // desired hash length = 32 = 256 bits
        ...params,
      })
      // result
      .then(
        ({
          hash, // hash as Uint8Array
          hashHex, // hash as hex-string
          encoded, // encoded hash, as required by argon2,
        }) => {
          return { hash, hashHex, encoded, derivationParams: params }
        }
      )
      // or error
      .catch((err) => {
        console.error('argon2 error', err)
        return err
      })
  )
}

export const derivation = {
  getDerivationParams,
  derivateKey,
}
//  const key = await window.crypto.subtle.generateKey(
//    {
//      name: AES_GCM,
//      length: AES_KEY_SIZE,
//    },
//    true,
//    ['encrypt', 'decrypt']
//  )
//
//  const { wrappingKey, derivation } = await derivateWrappingKeyFromPassword({
//    password,
//    derivationParams,
//  })
//
//  const aesParams = {
//    name: AES_GCM,
//    iv: window.crypto.getRandomValues(new Uint8Array(12)),
//    tagLength: AES_TAG_LENGTH,
//  }
//  const wrappedKey = await window.crypto.subtle.wrapKey(
//    RAW,
//    key,
//    wrappingKey,
//    aesParams
//  )
//  return {
//    key,
//    wrappedKey: {
//      key: wrappedKey,
//      ...aesParams,
//    },
//    derivation,
//  }
//}

const encrypt = (key, data) => {
  const arrayBufferData = new TextEncoder().encode(data)

  //Don't re-use initialization vectors!
  //Always generate a new iv every time your encrypt!
  //Recommended to use 12 bytes length
  const aesParams = {
    name: AES_GCM,
    iv: window.crypto.getRandomValues(new Uint8Array(12)),
    tagLength: AES_TAG_LENGTH,
  }
  return window.crypto.subtle
    .encrypt(aesParams, key, arrayBufferData)
    .then(function (encrypted) {
      return {
        encryptedData: new Uint8Array(encrypted),
        ...aesParams,
      }
    })
    .catch(function (err) {
      console.error(err)
    })
}

const decrypt = (key, iv) => {
  const data = new Uint8Array()
  window.crypto.subtle
    .decrypt(
      {
        name: AES_GCM,
        tagLength: AES_TAG_LENGTH,
        iv,
      },
      key,
      data
    )
    .then(function (decrypted) {
      return new Uint8Array(decrypted)
    })
    .catch(function (err) {
      console.error(err)
    })
}

export const aes = {
  generateKey: derivateKey,
  encrypt,
  decrypt,
}
