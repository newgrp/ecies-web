import { assert } from "https://unpkg.com/chai/chai.js";
import { eciesDecrypt, eciesEncrypt } from "./ecies.js";

mocha.setup({
  allowUncaught: false,
  checkLeaks: true,
  forbidPending: true,
  ui: "tdd",
});

const defaultParams = {
  format: "cryptokey",
  ecParams: { name: "ECDH", namedCurve: "P-256" },
  hkdfParams: { name: "HKDF", hash: "SHA-256" },
  aesParams: "AES-CTR",
  hmacParams: { name: "HMAC", hash: "SHA-256" },
};
const messageShort = "Hello, world!";
const messageLong =
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

// Converts a `string` to a `Uint8Array` by UTF-8 encoding.
function utf8Encode(s) {
  return new TextEncoder().encode(s);
}

// Converts a `Uint8Array` to a `string` by UTF-8 decoding.
function utf8Decode(s) {
  return new TextDecoder().decode(s);
}

// Asserts that a promise is rejected with a given error.
function assertIsRejected(promise, ...args) {
  let threw = false;
  promise
    .catch((e) => {
      threw = true;
      assert.throws(function () {
        throw e;
      }, ...args);
    })
    .then((_) => {
      if (!threw) assert.fail("Did not throw");
    });
}

// Runs a roundtrip test with the given elliptic curve parameters,
// `EciesParams`, and plaintext.
async function roundtripVariantTest(variant, plaintext) {
  const params = { ...defaultParams, ...variant };

  // Generate a keypair.
  const keyPair = await crypto.subtle.generateKey(
    /*algorithm=*/ params.ecParams,
    /*extractable=*/ true,
    /*keyUsages=*/ ["deriveKey"]
  );

  // Put the keys in the desired format.
  let publicKey = keyPair.publicKey;
  let privateKey = keyPair.privateKey;
  if (params.format != "cryptokey") {
    let pubFmt = params.format;
    let privFmt = params.format;
    if (params.format == "asn1") {
      pubFmt = "spki";
      privFmt = "pkcs8";
    }

    publicKey = await crypto.subtle.exportKey(pubFmt, publicKey);
    privateKey = await crypto.subtle.exportKey(privFmt, privateKey);
  }

  // Roundtrip the plaintext.
  const encryptedData = await eciesEncrypt(
    params,
    publicKey,
    utf8Encode(plaintext)
  );
  const roundtripPlaintext = utf8Decode(
    await eciesDecrypt(params, privateKey, encryptedData)
  );

  // Check that the roundtrip plaintext equals the original.
  assert.equal(roundtripPlaintext, plaintext);
}

// Tests that HMAC parameters are required for non-GCM AES modes.
async function noHMACParamsRejectedTest() {
  let params = structuredClone(defaultParams);
  params.hmacParams = undefined;

  // Generate a keypair.
  const keyPair = await crypto.subtle.generateKey(
    /*algorithm=*/ params.ecParams,
    /*extractable=*/ true,
    /*keyUsages=*/ ["deriveKey"]
  );

  for (const mode of ["AES-CTR", "AES-CBC"]) {
    // Check that the parameters are rejected.
    params.aesParams = mode;
    assertIsRejected(
      eciesEncrypt(params, keyPair.publicKey, utf8Encode(messageLong)),
      Error,
      "HMAC is required"
    );
  }
}

// Tests that encrypted data missing an HMAC is rejected if HMAC parameters are specified.
async function missingHMACRejectedTest() {
  let params = structuredClone(defaultParams);

  // Generate a keypair.
  const keyPair = await crypto.subtle.generateKey(
    /*algorithm=*/ { name: "ECDH", namedCurve: "P-256" },
    /*extractable=*/ true,
    /*keyUsages=*/ ["deriveKey"]
  );

  // Encrypt a plaintext.
  let encryptedData = await eciesEncrypt(
    params,
    keyPair.publicKey,
    utf8Encode(messageLong)
  );

  // Check that decryption fails without an HMAC.
  encryptedData.hmac = undefined;
  assertIsRejected(
    eciesDecrypt(params, keyPair.privateKey, encryptedData),
    Error,
    "HMAC"
  );
}

// Tests that encrypted data with an HMAC is rejected if HMAC parameters are not specified.
async function missingHMACParamsRejectedTest() {
  let params = structuredClone(defaultParams);

  // Generate a keypair.
  const keyPair = await crypto.subtle.generateKey(
    /*algorithm=*/ { name: "ECDH", namedCurve: "P-256" },
    /*extractable=*/ true,
    /*keyUsages=*/ ["deriveKey"]
  );

  // Encrypt a plaintext.
  const encryptedData = await eciesEncrypt(
    params,
    keyPair.publicKey,
    utf8Encode(messageLong)
  );

  // Check that decryption fails without HMAC parameters.
  params.hmacParams = undefined;
  assertIsRejected(
    eciesDecrypt(params, keyPair.privateKey, encryptedData),
    Error,
    "HMAC"
  );
}

suite("All tests", function () {
  for (const message of [messageShort, messageLong]) {
    test("Roundtrip with message length: " + message.length, async function () {
      await roundtripVariantTest({}, message);
    });
  }

  for (const format of ["cryptokey", "asn1", "jwk"]) {
    test("Roundtrip with format: " + format, async function () {
      await roundtripVariantTest({ format: format }, messageLong);
    });
  }

  for (const curve of [
    { name: "ECDH", namedCurve: "P-256" },
    { name: "ECDH", namedCurve: "P-384" },
    { name: "ECDH", namedCurve: "P-521" },
    // Currently, X25519 is not supported by most runtimes.
  ]) {
    test("Roundtrip with curve: " + curve.namedCurve, async function () {
      await roundtripVariantTest({ ecParams: curve }, messageLong);
    });
  }

  for (const hkdfParams of [
    { name: "HKDF", hash: "SHA-1" },
    { name: "HKDF", hash: "SHA-256" },
    { name: "HKDF", hash: "SHA-384" },
    { name: "HKDF", hash: "SHA-512" },
  ]) {
    test("Roundtrip with HKDF-" + hkdfParams.hash, async function () {
      await roundtripVariantTest({ hkdfParams: hkdfParams }, messageLong);
    });
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const info = crypto.getRandomValues(new Uint8Array(16));
  for (const [name, hkdfParams] of [
    ["HKDF salt", { salt: salt }],
    ["HKDF info", { info: info }],
    ["HKDF salt and info", { salt: salt, info: info }],
  ]) {
    test("Roundtrip with " + name, async function () {
      await roundtripVariantTest(
        { hkdfParams: { name: "HKDF", hash: "SHA-256", ...hkdfParams } },
        messageLong
      );
    });
  }

  for (const aesMode of ["AES-CTR", "AES-CBC", "AES-GCM"]) {
    test("Roundtrip with " + aesMode + " (string)", async function () {
      await roundtripVariantTest({ aesParams: aesMode }, messageLong);
    });
  }
  for (const aesParams of [
    { name: "AES-CTR" },
    { name: "AES-CBC" },
    { name: "AES-GCM" },
  ]) {
    test("Roundtrip with " + aesParams.name + " (object)", async function () {
      await roundtripVariantTest({ aesParams: aesParams }, messageLong);
    });
  }

  const iv16 = crypto.getRandomValues(new Uint8Array(16));
  const iv96 = crypto.getRandomValues(new Uint8Array(96));
  for (const aesParams of [
    { name: "AES-CTR", counter: iv16 },
    { name: "AES-CBC", iv: iv16 },
    { name: "AES-GCM", iv: iv96 },
  ]) {
    test("Roundtrip with " + aesParams.name + " and IV/ICB", async function () {
      await roundtripVariantTest({ aesParams: aesParams }, messageLong);
    });
  }

  for (const hmacParams of [
    { name: "HMAC", hash: "SHA-1" },
    { name: "HMAC", hash: "SHA-256" },
    { name: "HMAC", hash: "SHA-384" },
    { name: "HMAC", hash: "SHA-512" },
  ]) {
    test("Roundtrip with HMAC-" + hmacParams.hash, async function () {
      await roundtripVariantTest({ hmacParams: hmacParams }, messageLong);
    });
  }

  test("Roundtrip with AES-GCM and no HMAC", async function () {
    await roundtripVariantTest(
      { aesParams: "AES-GCM", hmacParams: undefined },
      messageLong
    );
  });

  test(
    "HMAC params are required for non-GCM AES modes",
    noHMACParamsRejectedTest
  );
  test(
    "Encrypted data must have an HMAC if HMAC parameters are specified",
    missingHMACRejectedTest
  );
  test(
    "HMAC parameters must be specified if encrypted data has an HMAC",
    missingHMACParamsRejectedTest
  );
});

mocha.run();
