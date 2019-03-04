cat << __EOF__ > index.js
var navigator = {};
navigator.userAgent = false;

var window = {};
__EOF__

cat ext/asmcrypto.js >> index.js

cat ext/yahoo.js >> index.js
cat ext/cj/cryptojs-312-core-fix.js >> index.js
cat ext/cj/x64-core.js >> index.js
cat ext/cj/cipher-core.js >> index.js
  cat ext/cj/aes.js >> index.js
  cat ext/cj/tripledes.js >> index.js
  cat ext/cj/enc-base64.js >> index.js
  cat ext/cj/md5.js >> index.js
cat ext/cj/sha1.js >> index.js
cat ext/cj/sha256.js >> index.js
  cat ext/cj/sha224.js >> index.js
cat ext/cj/sha512.js >> index.js
  cat ext/cj/sha384.js >> index.js
  cat ext/cj/ripemd160.js >> index.js
  cat ext/cj/hmac.js >> index.js
  cat ext/cj/pbkdf2.js >> index.js
cat ext/base64.js >> index.js
cat ext/jsbn.js >> index.js
cat ext/jsbn2.js >> index.js
cat ext/prng4.js >> index.js
cat ext/rng.js >> index.js
cat ext/rsa.js >> index.js
cat ext/rsa2.js >> index.js
  # cat ext/ec.js >> index.js
  # cat ext/ec-patch.js >> index.js
  # cat ext/json-sans-eval.js >> index.js

cat src/asn1-1.0.js >> index.js
cat src/asn1hex-1.1.js >> index.js
  cat src/asn1x509-1.0.js >> index.js
  cat src/asn1cms-1.0.js >> index.js
  cat src/asn1tsp-1.0.js >> index.js
  cat src/asn1cades-1.0.js >> index.js
  cat src/asn1csr-1.0.js >> index.js
  cat src/asn1ocsp-1.0.js >> index.js
cat src/base64x-1.1.js >> index.js
cat src/crypto-1.1.js >> index.js
  # cat src/ecdsa-modified-1.0.js >> index.js
  # cat src/ecparam-1.0.js >> index.js
  cat src/dsa-2.0.js >> index.js
  cat src/pkcs5pkey-1.0.js >> index.js
  cat src/keyutil-1.0.js >> index.js
cat src/rsapem-1.1.js >> index.js
cat src/rsasign-1.2.js >> index.js
  cat src/x509-1.1.js >> index.js
  # cat src/jws-3.3.js >> index.js
  # cat src/jwsjs-2.0.js >> index.js

cat << __EOF__ >> index.js
exports.X509 = X509;
exports.getRSAKeyFromData = KEYUTIL.getRSAKeyFromData;
exports.getRSAKeyFromEncryptedPKCS8PEM = PKCS5PKEY.getRSAKeyFromEncryptedPKCS8PEM;
exports.hashString = KJUR.crypto.Util.hashString;
__EOF__
