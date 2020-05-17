export const hasNativeCryptoSupport = () =>
  Boolean(
    window.crypto && window.crypto.getRandomValues && window.crypto.subtle
  )

const PBKDF2 = 'PBKDF2'
const PBKDF2_DEFAULT_ITERATIONS = 100000

const RAW = 'raw'
const SHA512 = 'SHA-512'

const AES_GCM = 'AES-GCM'
const AES_KEY_SIZE = 256
const AES_TAG_LENGTH = 96

const derivateWrappingKeyFromPassword = async ({
  password,
  derivationParams,
}) => {
  const encodedPassword = new TextEncoder().encode(password)

  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encodedPassword,
    { name: PBKDF2 },
    false,
    ['deriveBits', 'deriveKey']
  )
  const {
    iterations = PBKDF2_DEFAULT_ITERATIONS,
    salt = window.crypto.getRandomValues(new Uint8Array(16)),
  } = derivationParams

  const name = PBKDF2
  const wrappingKey = await window.crypto.subtle.deriveKey(
    {
      name,
      iterations,
      hash: SHA512,
      salt,
    },
    keyMaterial,
    { name: AES_GCM, length: AES_KEY_SIZE },
    true,
    ['wrapKey', 'unwrapKey']
  )
  return { wrappingKey, derivation: { name, iterations, salt } }
}

const generateKey = async (password, derivationParams) => {
  const key = await window.crypto.subtle.generateKey(
    {
      name: AES_GCM,
      length: AES_KEY_SIZE,
    },
    true,
    ['encrypt', 'decrypt']
  )

  const { wrappingKey, derivation } = await derivateWrappingKeyFromPassword({
    password,
    derivationParams,
  })

  const iv = window.crypto.getRandomValues(new Uint8Array(12))
  const wrappedKey = await window.crypto.subtle.wrapKey(RAW, key, wrappingKey, {
    name: AES_GCM,
    iv,
    tagLength: AES_TAG_LENGTH,
  })
  return {
    key,
    wrappedKey: {
      key: wrappedKey,
      iv,
    },
    derivation,
  }
}

const encrypt = (key, data) => {
  const textEncoder = new TextEncoder()
  const arrayBufferData = textEncoder.encode(data)
  //Don't re-use initialization vectors!
  //Always generate a new iv every time your encrypt!
  //Recommended to use 12 bytes length
  const iv = window.crypto.getRandomValues(new Uint8Array(12))
  return window.crypto.subtle
    .encrypt(
      {
        name: AES_GCM,
        iv,
        tagLength: AES_TAG_LENGTH,
      },
      key,
      arrayBufferData
    )
    .then(function (encrypted) {
      return new Uint8Array(encrypted)
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
  generateKey,
  encrypt,
  decrypt,
}
