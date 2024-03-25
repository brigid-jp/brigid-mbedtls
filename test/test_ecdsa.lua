local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

local entropy = mbedtls.entropy()
local ctr_drbg = mbedtls.ctr_drbg():seed(entropy)

-- openssl ecparam -genkey -name prime256v1 -noout >key1.pem
local key_pem = [[
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII7NAJCFPZZP6aLyblWg2kXD1tfRgPSjAWr8eqpYzKH8oAoGCCqGSM49
AwEHoUQDQgAE8xGMev+n8tdsj7S3yLkWYy84J5DYbh/cS6zrRM+c1x38WCfd2RMO
SDM4EkWx84hiV/HcVV5aLyeQF5pmTEsvoA==
-----END EC PRIVATE KEY-----
]]

-- printf 'Hello World!' | openssl dgst -sha256 -binary | xxd -i -c 8
local hash_bin = string.char(
  0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53,
  0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1, 0xd6, 0x5d,
  0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
  0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
)

-- printf 'Hello World!' | openssl dgst -sha256 -binary | openssl pkeyutl -sign -inkey key1.pem >signature.der
-- head -c 37 <signature.der | tail -b 32 | xxd -i -c 8
local r_bin = string.char(
  0x8d, 0x71, 0x3b, 0x65, 0x60, 0xc3, 0x33, 0xb8,
  0x1c, 0xad, 0x57, 0xe4, 0xee, 0xec, 0x28, 0xf0,
  0xb2, 0x2f, 0xe9, 0x9a, 0xc9, 0x0e, 0x80, 0x5b,
  0x7f, 0xe5, 0x27, 0xf1, 0x50, 0xe8, 0x10, 0xd7
)
-- tail -b 32 <signature.der | xxd -i -c 8
local s_bin = string.char(
  0x5f, 0x97, 0xf6, 0xc7, 0x80, 0xec, 0xff, 0xc0,
  0xbc, 0x21, 0x3e, 0xb6, 0x36, 0x0b, 0x42, 0x63,
  0xfb, 0x03, 0x05, 0x75, 0xbe, 0xbb, 0x36, 0xe4,
  0x8f, 0x95, 0x83, 0x1c, 0xa2, 0xf4, 0xea, 0xad
)

local group = mbedtls.ecp.group():load(mbedtls.ecp.DP_SECP256R1)
local pk = assert(mbedtls.pk():parse_key(key_pem, ctr_drbg))
local r = assert(mbedtls.mpi():read_binary(r_bin))
local s = assert(mbedtls.mpi():read_binary(s_bin))
assert(mbedtls.ecdsa.verify(group, hash_bin, pk:get_ec():get_public_key(), r, s))

local r, s = assert(mbedtls.ecdsa.sign_det_ext(group, pk:get_ec():get_key(), hash_bin, 0x09, ctr_drbg))
assert(mbedtls.ecdsa.verify(group, hash_bin, pk:get_ec():get_public_key(), r, s))
