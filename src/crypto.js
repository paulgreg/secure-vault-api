import argon2 from 'argon2-browser'

export const hasNativeCryptoSupport = () =>
  Boolean(
    window.crypto && window.crypto.getRandomValues && window.crypto.subtle
  )

const RAW = 'raw'
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
  const {
    hash, // hash as Uint8Array
    hashHex, // hash as hex-string
    encoded, // encoded hash, as required by argon2,
  } = await argon2.hash({
    pass: password,
    hashLen: 32, // desired hash length = 32 = 256 bits
    ...params,
  })

  return { hash, hashHex, encoded, derivationParams: params }
}

export const derivation = {
  getDerivationParams,
  derivateKey,
}

export const arrayBufferToUint8Array = (buffer) => {
  const dataViewer = new DataView(buffer)
  const array = new Uint8Array(buffer.byteLength)
  for (let i = 0; i < array.length; i++) array[i] = dataViewer.getUint8(i)
  return array
}

export const deserializeUint8Array = (data) =>
  new Uint8Array(Object.values(data))

export const createIdentity = async (password, input = {}) => {
  if (!password) throw new Error('PASSWORD_EMPTY')
  if (password.length < 8) throw new Error('PASSWORD_TOO_SHORT')

  const { derivationParams: inputDerivationParams } = input

  const { hash, derivationParams } = await derivateKey(
    password,
    inputDerivationParams
  )

  const keyEncryptionKey = await window.crypto.subtle.importKey(
    RAW,
    hash,
    AES_GCM,
    false,
    ['wrapKey']
  )

  const fileEncryptionKey = await generateFileEncryptionKey()

  const wrappedFileEncryptionKeyParams = {
    name: AES_GCM,
    iv: window.crypto.getRandomValues(new Uint8Array(12)),
    tagLength: AES_TAG_LENGTH,
  }

  const wrappedFileEncryptionKey = await window.crypto.subtle.wrapKey(
    RAW,
    fileEncryptionKey,
    keyEncryptionKey,
    wrappedFileEncryptionKeyParams
  )

  return {
    derivationParams,
    keyEncryptionKey,
    fileEncryptionKey,
    wrappedFileEncryptionKey: arrayBufferToUint8Array(wrappedFileEncryptionKey),
    wrappedFileEncryptionKeyParams,
  }
}

export const loadIdentity = async (password, input = {}) => {
  const {
    derivationParams,
    wrappedFileEncryptionKey,
    wrappedFileEncryptionKeyParams,
  } = input

  if (!password) throw new Error('PASSWORD_EMPTY')
  if (password.length < 8) throw new Error('PASSWORD_TOO_SHORT')
  if (!wrappedFileEncryptionKey) throw new Error('KEY_MISSING')
  if (!wrappedFileEncryptionKeyParams) throw new Error('KEY_PARAMS_MISSING')
  if (!wrappedFileEncryptionKeyParams.iv)
    throw new Error('KEY_PARAMS_IV_MISSING')

  const { hash } = await derivateKey(password, derivationParams)

  const keyEncryptionKey = await window.crypto.subtle.importKey(
    RAW,
    hash,
    AES_GCM,
    false,
    ['unwrapKey']
  )

  const fileEncryptionKey = await window.crypto.subtle.unwrapKey(
    RAW,
    deserializeUint8Array(wrappedFileEncryptionKey),
    keyEncryptionKey,
    {
      name: AES_GCM,
      tagLength: AES_TAG_LENGTH,
      iv: deserializeUint8Array(wrappedFileEncryptionKeyParams.iv),
    },
    { name: AES_GCM },
    false,
    ['encrypt', 'decrypt']
  )

  return { fileEncryptionKey }
}

const generateFileEncryptionKey = async () =>
  window.crypto.subtle.generateKey(
    {
      name: AES_GCM,
      length: AES_KEY_SIZE,
    },
    true,
    ['encrypt', 'decrypt']
  )

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
