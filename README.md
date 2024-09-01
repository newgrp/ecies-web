# ecies-web

This library performs Elliptic Curve Integrated Encryption Scheme (ECIES)
encryption and decryption. ECIES is defined in
[SEC 1: Elliptic Curve Cyrptography](https://www.secg.org/sec1-v2.pdf) section
5.1, which summarizes the algorithm as follows:

> ECIES is a public-key encryption scheme based on ECC. It is designed to be
> semantically secure in the presence of an adversary capable of launching
> chosen-plaintext and chosen-ciphertext attacks.

This library implements ECIES for browsers, using the
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
for all cryptographic primitives. As such, support and security may depend on
your browser.

> **WARNING:** I (the author) do not know what I'm doing. There are likely
> meaningful sucirty concerns with this library that I, as a cryptography amateur,
> cannot see. The library is probably not suitable for "important" use cases. If
> you'd like to use this library for something "important", please get this code
> and your use case reviewed by a cryptography professional (i.e., someone with a
> PhD in crytography and experience with vulnerabilities in real-world
> implementations) and ideally share your findings with me.

- [Example](#example)
- [Overview of ECIES](#overview-of-ecies)
- [API](#api)
  - [`eciesEncrypt()`](#eciesencrypt)
  - [`eciesDecrypt()`](#eciesdecrypt)
- [Data types](#data-types)
  - [`EciesParams`](#eciesparams)
  - [`EciesEncryptedData`](#eciesencrypteddata)
  - [Key formats](#key-formats)

## Example

```js
// Generate a key pair to use for the example.
const keyPair = await crypto.subtle.generateKey(
    /*algorithm=*/{ name: "ECDH", namedCurve: "P-256" },
    /*extractable=*/false,
    /*keyUsages=*/["deriveKey"]
)

// Decide what message to encrypt and what parameters to use.
const eciesParams = {
    format: "cryptokey",
    ecParams: { name: "ECDH", namedCurve: "P-256" },
    hkdfParams: { name: "HKDF", hash: "SHA-256" },
    aesParams: "AES-CTR",
    hmacParams: { name: "HMAC", hash: "SHA-256" }
}
const message = "Hello, world!"
const messageBytes = new TextEncoder().encode(message)

// Encrypt the message.
const encryptedData = await eciesEncrypt(
    /*params=*/eciesParams,
    /*publicKey=*/keyPair.publicKey,
    /*plaintext=*/messageBytes
)

// Decrypt the message.
const roundtripBytes = await eciesDecrypt(
    /*params=*/eciesParams,
    /*privateKey=*/keyPair.privateKey,
    /*encryptedData=*/encryptedData
)
const roundtripMessage = new TextDecoder().decode(message)

// The decrypted message equals the original one!
console.assert(roundtripMessage == message)
```

## Overview of ECIES

ECIES is used to encrypt data to an Elliptic Curve public key so that the data
can only be decrypted with the corresponding private key. ECIES is a hybrid
encryption scheme, so encryption does not use the Elliptic Curve keys directly
but instead uses them to derive symmetric keys, which are then used to actually
encrypt the data. ECIES also typically includes an HMAC using the derived
symmetric keys to authenticate the integrity of the data.

At a high level, the steps for encryption are:

1. Generate an ephemeral keypair
1. Perform Diffie-Hellman between the given public key and ephemeral private key
   to derive a shared secret
1. Use the key derivation function HKDF to create AES and HMAC keys from the
   shared secret
1. Encrypt the plaintext data using the AES key to produce a ciphertext
1. Compute an HMAC over the AES IV/ICB (public AES parameters) and the
   ciphertext
1. Return the ephemeral public key, the AES IV/ICB, the ciphertext, and the HMAC

The steps for decryption are:

1. Extract the ephemeral public key
1. Perform Diffie-Hellman between the given private key and ephemeral public key
   to derive the same shared secret as in encryption
1. Use the same HKDF parameters as encryption to compute the same AES and HMAC
   keys from the shared secret
1. Verify the HMAC over the AES IV/ICB and the ciphertext
1. Decrypt the ciphertext and return it

When AES operates in GCM mode, the symmetric encryption provides its own
authenticity guarantees, so this library allows the HMAC to be omitted when
using AES-GCM.

## API

The public API of `ecies-web` consists of two functions
[`eciesEncrypt()`](#eciesencrypt) and [`eciesDecrypt()`](#eciesdecrypt).

### `eciesEncrypt()`

Encrypts a message (the "plaintext") to a given public key. `eciesEncrypt()`
accepts the following parameters, in order.

#### `params`

The [`EciesParams`](#eciesparams) to use for this encryption.

#### `publicKey`

The public key to encrypt the plaintext to, in the format specified by
`params.format`. See [Key formats](#key-formats) for more info.

#### `plaintext`

The message to encrypt, given as an
[`ArrayBuffer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer),
a
[`TypedArray`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray),
or a
[`DataView`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DataView).

#### Return value

An [`EciesEncryptedData`](#eciesencrypteddata) object. The `ephemeralPublicKey`
field is given in the format specified by `params.format`. The `ciphertext` and
`hmac` fields (if present) will be given as
[`ArrayBuffer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer)s.

### `eciesDecrypt()`

Decrypts a message (the "ciphertext") using a private key. `eciesDecrypt()`
accepts the following parameters, in order.

#### `params`

The [`EciesParams`](#eciesparams) originally used for encryption.

#### `privateKey`

The private key corresponding to the public key that was originally used to
encrypt the ciphertext. Must be given in the format specified by
`params.format`. See [Key formats](#key-formats) for more info.

#### `encryptedData`

An [`EciesEncryptedData`](#eciesencrypteddata) giving the encrypted data to be
decrypted. The `ephemeralPublicKey` field must be in the format given by
`params.format`.

#### Return value

The decrypted plaintext as an
[`ArrayBuffer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer).

## Data types

`ecies-web` uses two custom dictionary data structures in its API:
[`EciesParams`](#eciesparams) and `EciesEncryptedData`. It also supports several
different [key formats](#key-formats) for both input and output.

### `EciesParams`

Parameters for ECIES encryption. `EciesParams` is used as an input to both
`eciesEncrypt()` and `eciesDecrypt()`. An `EciesParams` object is a dictionary
with the following keys.

#### `format`

The format to use for Elliptic Curve keys. See [Key formats](#key-formats) for
more details.

#### `ecParams`

Elliptic Curve parameters in the form of either an
[`EcKeyImportParams`](https://developer.mozilla.org/en-US/docs/Web/API/EcKeyImportParams)
object, the object `{ name: "X25519" }`, or the string `"X25519"`.

**NOTE:** At time of writing (2024-08-30), X25519 is not yet widely supported in
browsers.

#### `hkdfParams`

HKDF parameters as an
[`HkdfParams`](https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams)
object. The `salt` and `info` fields may be omitted, in which case they default
to empty buffers.

#### `aesParams`

AES mode and parameters as either a string (`"AES-CTR"`, `"AES-CBC"`, or
`"AES-GCM"`) or an appropriate Web Crypto API parameters object for the desired
mode
([`AesCtrParams`](https://developer.mozilla.org/en-US/docs/Web/API/AesCtrParams),
[`AesCbcParams`](https://developer.mozilla.org/en-US/docs/Web/API/AesCbcParams),
or
[`AesGcmParams`](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams)).

If an object is passed, all fields except `name` may be omitted, in which case
they will be given default values. The default values for the `counter` and `iv`
fields are zero-filled buffers of the appropriate length for the AES mode chosen
(96 bytes for AES-GCM). The default value for the `length` field in AES-CTR is
64\.

#### `hmacParams` (optional)

HMAC parameters in the form of
[`HmacImportParams`](https://developer.mozilla.org/en-US/docs/Web/API/HmacImportParams).

This field must be specified unless AES-GCM is used.

### `EciesEncryptedData`

An ECIES-encrypted ciphertext, together with additional data needed to decrypt
it. `EciesEncryptedData` is the output of `eciesEncrypt()` and an input to
`eciesDecrypt()`. An `EciesEncryptedData` object contains the following fields.

#### `ephemeralPublicKey`

The ephemeral public key used for this encryption, according to the key format
in the `EciesParams` for this encryption.

#### `ciphertext`

The encrypted message as an
[`ArrayBuffer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer),
a
[`TypedArray`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray),
or a
[`DataView`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DataView).

#### `hmac` (optional)

An HMAC over the AES IV/ICB concatenated with `ciphertext`, given as an
[`ArrayBuffer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer),
a
[`TypedArray`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray),
or a
[`DataView`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DataView).
Must be included unless using AES-GCM.

### Key formats

`ecies-web` supports the following key formats for input and output keys,
adapted from the supported formats for
[`SubtleCrypto.importKey()`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#format).

#### `"asn1"`

For public keys, the key is given as a DER-encoded `SubjectPublicKeyInfo`
message as defined by [RFC 3279](https://www.rfc-editor.org/rfc/rfc3279) and
[RFC 5480](https://www.rfc-editor.org/rfc/rfc5480) (which corresponds to the
`"spki"` option for `SubtleCrypto.importKey()`). For private keys, the key is
given as a DER-encoded `PrivateKeyInfo` message as defined by
[RFC 5208](https://www.rfc-editor.org/rfc/rfc5208) and
[RFC 5915](https://www.rfc-editor.org/rfc/rfc5915) (which corresponds to the
`"pkcs8"` option for `SubtleCrypto.importKey()`).

In both cases, the data must be given as an
[`ArrayBuffer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer),
a
[`TypedArray`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray),
or a
[`DataView`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DataView).

#### `"jwk"`

Both public and private keys are given as JSON Web Keys (JWKs), as defined by
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517).

#### `"cryptokey"`

Both public and private keys are given as
[`CryptoKey`](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey)
objects with the appropriate settings. Input keys must have `"deriveKey"` in
their allowed usages. Output keys will have `"deriveKey"` as their only allowed
usage.
