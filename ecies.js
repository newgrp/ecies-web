// Key size in bytes for AES-256.
const aes256KeySize = 32;

// Concatenates byte arrays into a single `Uint8Array`.
function concatByteArrays(...arrays) {
  let u8arrays = arrays.map((arr) => new Uint8Array(arr));

  let length = 0;
  for (const arr of u8arrays) {
    length += arr.length;
  }

  let ret = new Uint8Array(length);
  let idx = 0;
  for (const arr of u8arrays) {
    ret.set(arr, idx);
    idx += arr.length;
  }
  return ret;
}

// Scrubs all data from an `ArrayBuffer`.
function cleanse(buf) {
  let view = new DataView(buf);
  for (let i = 0; i < view.byteLength; i++) {
    view.setUint8(i, 0);
  }
}

// Converts an `EciesParams` key format to a Web Crypto PKI key format for a public key.
//
// The input format must not be `"cryptokey"`.
function getPublicKeyFormat(format) {
  switch (format) {
    case "asn1":
      return "spki";
    case "jwk":
      return "jwk";
    default:
      throw new Error("Unrecognized key format: " + format);
  }
}

// Converts an `EciesParams` key format to a Web Crypto PKI key format for a private key.
//
// The input format must not be `"cryptokey"`.
function getPrivateKeyFormat(format) {
  switch (format) {
    case "asn1":
      return "pkcs8";
    case "jwk":
      return "jwk";
    default:
      throw new Error("Unrecognized key format: " + format);
  }
}

// Normalizes HKDF parameters by populating fields with defaults if necessary.
function normalizeHKDFParams(hkdfParams) {
  if (hkdfParams.salt === undefined) {
    hkdfParams.salt = new ArrayBuffer();
  }
  if (hkdfParams.info === undefined) {
    hkdfParams.info = new ArrayBuffer();
  }
  return hkdfParams;
}

// Normalizes AES parameters by populating fields with defaults if necessary.
function normalizeAESParams(aesParams) {
  if (typeof aesParams === "string") {
    aesParams = { name: aesParams };
  }

  // It is important in AES to use a different IV/ICB for each encryption performed with the same
  // key. If you don't, then an attacker can potentially attack all the encryptions performed with
  // the same IV/ICB using e.g., known plaintext attacks. For this reason, IVs/ICBs are typically
  // randomly generated.
  //
  // However, each AES key in ECIES is derived from a different, random ephemeral keypair, and
  // that AES key is only used for one encryption. Therefore, it is safe to use a fixed IV/ICB. In
  // fact, this is recommended by SEC 1, ver 2.0, section 3.8.
  switch (aesParams.name) {
    case "AES-CTR":
      if (aesParams.counter === undefined) {
        aesParams.counter = new ArrayBuffer(16);
      }
      if (aesParams.length === undefined) {
        aesParams.length = 64;
      }
      break;
    case "AES-CBC":
      if (aesParams.iv === undefined) {
        aesParams.iv = new ArrayBuffer(16);
      }
      break;
    case "AES-GCM":
      if (aesParams.iv === undefined) {
        aesParams.iv = new ArrayBuffer(96);
      }
      break;
    default:
      throw new Error("Unsupported AES mode: " + aesParams.name);
  }
  return aesParams;
}

// Validates an `EciesParams` object and returns it.
function validateParams(params) {
  params.hkdfParams = normalizeHKDFParams(params.hkdfParams);
  params.aesParams = normalizeAESParams(params.aesParams);
  if (params.aesParams.name != "AES-GCM" && params.hmacParams === undefined) {
    throw new Error("HMAC is required unless using AES-GCM");
  }
  return params;
}

// Gets the IV or ICB from AES parameters.
function getIVOrICB(aesParams) {
  if (aesParams.counter !== undefined) {
    return aesParams.counter;
  }
  if (aesParams.iv !== undefined) {
    return aesParams.iv;
  }
  return new Uint8Array();
}

// Returns the key size to use with the given `HmacImportParams`, or 0 if the input is `undefined`.
function getHMACKeySize(hmacParams) {
  if (hmacParams === undefined) {
    return 0;
  }
  if (hmacParams.length !== undefined) {
    // `HmacImportParams.length` is the length in bits, so round up to the nearest byte.
    return (hmacParams.length + 7) / 8;
  }
  switch (hmacParams.hash) {
    case "SHA-1":
      // Use of SHA-1 is strongly discouraged, but we'll allow it.
      return 20;
    case "SHA-256":
      return 32;
    case "SHA-384":
      return 48;
    case "SHA-512":
      return 64;
    default:
      throw new Error("Unsupported hash algorithm: " + hmacParams.hash);
  }
}

// Derives AES and HMAC keys from public and private EC keys via ECDH-HKDF.
async function eciesDerive(params, pub, priv) {
  let hkdfRaw = null;
  let aesRaw = null;
  let hmacRaw = null;

  try {
    // Derive a shared secret.
    const hmacKeySize = getHMACKeySize(params.hmacParams);
    const hkdfKey = await crypto.subtle.deriveKey(
      /*algorithm=*/ { name: params.ecParams.name, public: pub },
      /*baseKey=*/ priv,
      /*derivedKeyType=*/ params.hkdfParams,
      /*extractable=*/ false,
      /*keyUsages=*/ ["deriveBits"]
    );
    hkdfRaw = await crypto.subtle.deriveBits(
      /*algorithm=*/ params.hkdfParams,
      /*baseKey=*/ hkdfKey,
      /*length=*/ 8 * (aes256KeySize + hmacKeySize)
    );

    let ret = {};

    // Extract an AES key from the shared secret.
    aesRaw = hkdfRaw.slice(0, aes256KeySize);
    ret.aesKey = await crypto.subtle.importKey(
      /*format=*/ "raw",
      /*keyData=*/ aesRaw,
      /*algorithm=*/ params.aesParams.name,
      /*extractable=*/ false,
      /*keyUsages=*/ ["decrypt", "encrypt"]
    );

    if (params.hmacParams !== undefined) {
      // Extract an HMAC key from the shared secret.
      hmacRaw = hkdfRaw.slice(aes256KeySize, aes256KeySize + hmacKeySize);
      ret.hmacKey = await crypto.subtle.importKey(
        /*format=*/ "raw",
        /*keyData=*/ hmacRaw,
        /*algorithm=*/ params.hmacParams,
        /*extractable=*/ false,
        /*keyUsages=*/ ["sign", "verify"]
      );
    }

    return ret;
  } finally {
    // Scrub shared secrets so that an attacker can't recover them by walking memory. We can
    // only hope that the browser does the same with its `CryptoKey`s.
    if (hkdfRaw) cleanse(hkdfRaw);
    if (aesRaw) cleanse(aesRaw);
    if (hmacRaw) cleanse(hmacRaw);
  }
}

// Encrypts the plaintext to the public key using ECIES.
export async function eciesEncrypt(params, publicKey, plaintext) {
  params = validateParams(params);
  let ret = {};

  if (params.format != "cryptokey") {
    // Import the public key as a `CryptoKey`.
    publicKey = await crypto.subtle.importKey(
      /*format=*/ getPublicKeyFormat(params.format),
      /*keyData=*/ publicKey,
      /*algorithm=*/ params.ecParams,
      /*extractable=*/ false,
      /*keyUsages=*/ []
    );
  }

  // Generate an ephemeral keypair.
  const ephemeralKeyPair = await crypto.subtle.generateKey(
    /*algorithm=*/ publicKey.algorithm,
    /*extractable=*/ true,
    /*keyUsages=*/ ["deriveKey"]
  );

  // Extract the ephemeral public key to return later.
  if (params.format != "cryptokey") {
    ret.ephemeralPublicKey = await crypto.subtle.exportKey(
      /*format=*/ getPublicKeyFormat(params.format),
      /*key=*/ ephemeralKeyPair.publicKey
    );
  } else {
    ret.ephemeralPublicKey = ephemeralKeyPair.publicKey;
  }

  // Derive shared secret keys.
  const eciesKeys = await eciesDerive(
    params,
    publicKey,
    ephemeralKeyPair.privateKey
  );

  // Encrypt the plaintext using AES.
  ret.ciphertext = await crypto.subtle.encrypt(
    /*algorithm=*/ params.aesParams,
    /*key=*/ eciesKeys.aesKey,
    /*data=*/ plaintext
  );

  if (params.hmacParams !== undefined) {
    // Compute an HMAC over the IV/ICB || ciphertext.
    ret.hmac = await crypto.subtle.sign(
      /*algorithm=*/ "HMAC",
      /*key=*/ eciesKeys.hmacKey,
      /*data=*/ concatByteArrays(getIVOrICB(params.aesParams), ret.ciphertext)
        .buffer
    );
  }

  return ret;
}

// Decrypts the ciphertext using ECIES with the given private key.
export async function eciesDecrypt(params, privateKey, encryptedData) {
  params = validateParams(params);
  if (params.hmacParams === undefined && encryptedData.hmac !== undefined) {
    throw new Error(
      "Encrypted data includes an HMAC but no HMAC parameters were provided"
    );
  }
  if (params.hmacParams !== undefined && encryptedData.hmac === undefined) {
    throw new Error(
      "HMAC verification was requested but encrypted data does not include an HMAC"
    );
  }

  let ephemeralPublicKey = encryptedData.ephemeralPublicKey;
  if (params.format != "cryptokey") {
    // Import the keys as `CryptoKey`s.
    ephemeralPublicKey = await crypto.subtle.importKey(
      /*format=*/ getPublicKeyFormat(params.format),
      /*keyData=*/ ephemeralPublicKey,
      /*algorithm=*/ params.ecParams,
      /*extractable=*/ false,
      /*keyUsages=*/ []
    );
    privateKey = await crypto.subtle.importKey(
      /*format=*/ getPrivateKeyFormat(params.format),
      /*keyData=*/ privateKey,
      /*algorithm=*/ params.ecParams,
      /*extractable=*/ false,
      /*keyUsages=*/ ["deriveKey"]
    );
  }

  // Derive shared secret keys.
  const eciesKeys = await eciesDerive(params, ephemeralPublicKey, privateKey);

  if (params.hmacParams !== undefined) {
    // Verify the HMAC.
    const ok = await crypto.subtle.verify(
      /*algorithm=*/ "HMAC",
      /*key=*/ eciesKeys.hmacKey,
      /*signature=*/ encryptedData.hmac,
      /*data=*/ concatByteArrays(
        getIVOrICB(params.aesParams),
        encryptedData.ciphertext
      ).buffer
    );
    if (!ok) {
      throw new Error("HMAC verification failed");
    }
  }

  // Decrypt the ciphertext.
  return crypto.subtle.decrypt(
    /*algorithm=*/ params.aesParams,
    /*key=*/ eciesKeys.aesKey,
    /*data=*/ encryptedData.ciphertext
  );
}
