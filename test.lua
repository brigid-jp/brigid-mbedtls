local test; test = {

----------------------------------------------------------------------

debug = (tonumber(os.getenv "BRIGID_MBEDTLS_DEBUG") or 0) > 0;

assume_fail = function (f, ...)
  local result, message = f(...)
  if test.debug then
    print("assume_fail: "..message)
  end
  assert(not result)
  assert(message)
end;

assume_error = function (...)
  local result, message = pcall(...)
  if test.debug then
    print("assume_error: "..message)
  end
  assert(not result)
  assert(message)
end;

----------------------------------------------------------------------

secp256r1_1 = {
-- openssl ecparam -genkey -name prime256v1 -noout >secp256r1_1-key.pem
key_pem = [[
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII7NAJCFPZZP6aLyblWg2kXD1tfRgPSjAWr8eqpYzKH8oAoGCCqGSM49
AwEHoUQDQgAE8xGMev+n8tdsj7S3yLkWYy84J5DYbh/cS6zrRM+c1x38WCfd2RMO
SDM4EkWx84hiV/HcVV5aLyeQF5pmTEsvoA==
-----END EC PRIVATE KEY-----
]];
-- openssl ec -pubout <secp256r1_1-key.pem >secp256r1_1-pub.pem
pub_pem = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xGMev+n8tdsj7S3yLkWYy84J5DY
bh/cS6zrRM+c1x38WCfd2RMOSDM4EkWx84hiV/HcVV5aLyeQF5pmTEsvoA==
-----END PUBLIC KEY-----
]];
-- openssl pkey -outform der <secp256r1_1-key.pem | head -c 39 | tail -c 32 | xxd -i -c 8
key_bin = string.char(
  0x8e, 0xcd, 0x00, 0x90, 0x85, 0x3d, 0x96, 0x4f,
  0xe9, 0xa2, 0xf2, 0x6e, 0x55, 0xa0, 0xda, 0x45,
  0xc3, 0xd6, 0xd7, 0xd1, 0x80, 0xf4, 0xa3, 0x01,
  0x6a, 0xfc, 0x7a, 0xaa, 0x58, 0xcc, 0xa1, 0xfc
);
-- openssl pkey -pubin -outform der <secp256r1_1-pub.pem | tail -b 65 | xxd -i -c 8
pub_bin = string.char(
  0x04, 0xf3, 0x11, 0x8c, 0x7a, 0xff, 0xa7, 0xf2,
  0xd7, 0x6c, 0x8f, 0xb4, 0xb7, 0xc8, 0xb9, 0x16,
  0x63, 0x2f, 0x38, 0x27, 0x90, 0xd8, 0x6e, 0x1f,
  0xdc, 0x4b, 0xac, 0xeb, 0x44, 0xcf, 0x9c, 0xd7,
  0x1d, 0xfc, 0x58, 0x27, 0xdd, 0xd9, 0x13, 0x0e,
  0x48, 0x33, 0x38, 0x12, 0x45, 0xb1, 0xf3, 0x88,
  0x62, 0x57, 0xf1, 0xdc, 0x55, 0x5e, 0x5a, 0x2f,
  0x27, 0x90, 0x17, 0x9a, 0x66, 0x4c, 0x4b, 0x2f,
  0xa0
);
};

secp256r1_2 = {
-- openssl ecparam -genkey -name prime256v1 -noout >secp256r1_2-key.pem
key_pem = [[
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHo/qsgIjbsESR9cTXPZPEx3x1gpYUOi5yUQYuEhNUUnoAoGCCqGSM49
AwEHoUQDQgAE7jXlwc8p4XvwZszRI4y2/m5XQUeg+s7p++8t6I1po1zcyyEcO5uS
5iu/cjRfBnGU0AQ7ak3vZY5x7j275BW3hQ==
-----END EC PRIVATE KEY-----
]];
-- openssl ec -pubout <secp256r1_2-key.pem >secp256r1_2-pub.pem
pub_pem = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7jXlwc8p4XvwZszRI4y2/m5XQUeg
+s7p++8t6I1po1zcyyEcO5uS5iu/cjRfBnGU0AQ7ak3vZY5x7j275BW3hQ==
-----END PUBLIC KEY-----
]];
};

ecdh = {
-- openssl pkeyutl -derive -inkey secp256r1_1-key.pem -peerkey secp256r1_2-pub.pem | xxd -i -c 8
secret = string.char(
  0x98, 0xe0, 0xed, 0x1d, 0xbb, 0x03, 0x73, 0xab,
  0x89, 0x3d, 0x5b, 0xe9, 0xa7, 0x90, 0x80, 0x7d,
  0xd2, 0x77, 0xcb, 0xda, 0xa8, 0x5d, 0xfb, 0x22,
  0xdc, 0x4d, 0x1e, 0xe6, 0x5a, 0x86, 0x5e, 0xa8
);
};

-- printf 'Hello World!' | openssl dgst -sha256 -binary | openssl pkeyutl -sign -inkey secp256r1_1-key.pem >signature.der
ecdsa = {
-- head -c 37 <signature.der | tail -b 32 | xxd -i -c 8
r = string.char(
  0x8d, 0x71, 0x3b, 0x65, 0x60, 0xc3, 0x33, 0xb8,
  0x1c, 0xad, 0x57, 0xe4, 0xee, 0xec, 0x28, 0xf0,
  0xb2, 0x2f, 0xe9, 0x9a, 0xc9, 0x0e, 0x80, 0x5b,
  0x7f, 0xe5, 0x27, 0xf1, 0x50, 0xe8, 0x10, 0xd7
);
-- tail -b 32 <signature.der | xxd -i -c 8
s = string.char(
  0x5f, 0x97, 0xf6, 0xc7, 0x80, 0xec, 0xff, 0xc0,
  0xbc, 0x21, 0x3e, 0xb6, 0x36, 0x0b, 0x42, 0x63,
  0xfb, 0x03, 0x05, 0x75, 0xbe, 0xbb, 0x36, 0xe4,
  0x8f, 0x95, 0x83, 0x1c, 0xa2, 0xf4, 0xea, 0xad
);
};

----------------------------------------------------------------------

sha256 = {
message = "Hello World!";
secret = "secret";
hash = string.char(
  0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53,
  0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1, 0xd6, 0x5d,
  0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
  0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
);
hmac = string.char(
  0x6f, 0xa7, 0xb4, 0xde, 0xa2, 0x8e, 0xe3, 0x48,
  0xdf, 0x10, 0xf9, 0xbb, 0x59, 0x5a, 0xd9, 0x85,
  0xff, 0x15, 0x0a, 0x4a, 0xdf, 0xd6, 0x13, 0x1c,
  0xca, 0x67, 0x7d, 0x9a, 0xce, 0xe0, 0x7d, 0xc6
);
};

----------------------------------------------------------------------

-- https://datatracker.ietf.org/doc/html/rfc8188
rfc8188 = {
CEK = string.char(
  0xff, 0x09, 0xe2, 0xca, 0xd0, 0x7e, 0xa1, 0xfb,
  0x1c, 0x64, 0x38, 0x78, 0xb5, 0xb4, 0xa3, 0x1f
);
NONCE = string.char(
  0x05, 0xcb, 0x3c, 0x82, 0x42, 0x11, 0x28, 0xb2,
  0x3c, 0x19, 0xe2, 0x3c
);
plaintext = "I am the walrus\2";
ciphertext = string.char(
  0xf8, 0xd0, 0x15, 0xb9, 0xbd, 0xaa, 0x16, 0x00,
  0x44, 0xb9, 0x02, 0x91, 0x6a, 0x9a, 0x19, 0xbb
);
tag = string.char(
  0xe2, 0x31, 0x90, 0x8b, 0xda, 0xdc, 0xc1, 0x01,
  0xd4, 0xf0, 0xfe, 0x97, 0x2f, 0x13, 0x86, 0x38
);
};

----------------------------------------------------------------------

}
return test
