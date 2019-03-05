#!/bin/sh

# sh build.sh > jsrsasign.js
# sh build.sh | terser --module -c -m > jsrsasign.js

cat << __EOF__
var navigator = {};
navigator.userAgent = false;

var window = {};
__EOF__

cat ext/asmcrypto.js

cat ext/yahoo.js
cat ext/cj/cryptojs-312-core-fix.js
# cat ext/cj/x64-core.js
cat ext/cj/cipher-core.js
  cat ext/cj/aes.js
  cat ext/cj/tripledes.js
  # cat ext/cj/enc-base64.js
  # cat ext/cj/md5.js
# cat ext/cj/sha1.js
# cat ext/cj/sha256.js
  # cat ext/cj/sha224.js
# cat ext/cj/sha512.js
  # cat ext/cj/sha384.js
  # cat ext/cj/ripemd160.js
  # cat ext/cj/hmac.js
  # cat ext/cj/pbkdf2.js
cat ext/base64.js
cat ext/jsbn.js
cat ext/jsbn2.js
cat ext/prng4.js
cat ext/rng.js
cat ext/rsa.js
cat ext/rsa2.js
        # cat ext/ec.js
        # cat ext/ec-patch.js
        # cat ext/json-sans-eval.js

cat src/asn1hex-1.1.js
cat src/asn1-1.0.js
  cat src/asn1x509-1.0.js
  # cat src/asn1cms-1.0.js
  # cat src/asn1tsp-1.0.js
  # cat src/asn1cades-1.0.js
  # cat src/asn1csr-1.0.js
  # cat src/asn1ocsp-1.0.js
cat src/base64x-1.1.js
cat src/crypto-1.1.js
        # cat src/ecdsa-modified-1.0.js
        # cat src/ecparam-1.0.js
  # cat src/dsa-2.0.js
  cat src/keyutil-1.0.js
cat src/rsapem-1.1.js
cat src/rsasign-1.2.js
  cat src/x509-1.1.js
        # cat src/jws-3.3.js
        # cat src/jwsjs-2.0.js

cat << __EOF__

module.exports = {
  string_to_bytes,
  hex_to_bytes,
  base64_to_bytes,
  bytes_to_string,
  bytes_to_hex,
  bytes_to_base64,

  X509,
  RSAKey,
  KEYUTIL,
  KJUR,
};
__EOF__
