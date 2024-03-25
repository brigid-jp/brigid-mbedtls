local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

local entropy = mbedtls.entropy()
local ctr_drbg = mbedtls.ctr_drbg():seed(entropy)

-- openssl ecparam -genkey -name prime256v1 -noout >key1.pem
local key1_pem = [[
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII7NAJCFPZZP6aLyblWg2kXD1tfRgPSjAWr8eqpYzKH8oAoGCCqGSM49
AwEHoUQDQgAE8xGMev+n8tdsj7S3yLkWYy84J5DYbh/cS6zrRM+c1x38WCfd2RMO
SDM4EkWx84hiV/HcVV5aLyeQF5pmTEsvoA==
-----END EC PRIVATE KEY-----
]]

-- openssl ecparam -genkey -name prime256v1 -noout >key2.pem
-- openssl ec -pubout <key2.pem >pubkey2.pem
local pubkey2_pem = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7jXlwc8p4XvwZszRI4y2/m5XQUeg
+s7p++8t6I1po1zcyyEcO5uS5iu/cjRfBnGU0AQ7ak3vZY5x7j275BW3hQ==
-----END PUBLIC KEY-----
]]

-- openssl pkeyutl -derive -inkey key2.pem -peerkey pubkey1.pem | xxd -i -c 8
local secret_bin = string.char(
  0x98, 0xe0, 0xed, 0x1d, 0xbb, 0x03, 0x73, 0xab,
  0x89, 0x3d, 0x5b, 0xe9, 0xa7, 0x90, 0x80, 0x7d,
  0xd2, 0x77, 0xcb, 0xda, 0xa8, 0x5d, 0xfb, 0x22,
  0xdc, 0x4d, 0x1e, 0xe6, 0x5a, 0x86, 0x5e, 0xa8
)

local group = mbedtls.ecp.group():load(mbedtls.ecp.DP_SECP256R1)
local pk1 = assert(mbedtls.pk():parse_key(key1_pem, ctr_drbg))
local pk2 = assert(mbedtls.pk():parse_public_key(pubkey2_pem, ctr_drbg))
local ecdh = assert(mbedtls.ecdh():setup(mbedtls.ecp.DP_SECP256R1))
assert(ecdh:get_params(pk1:get_ec(), mbedtls.ecdh.OURS))
assert(ecdh:get_params(pk2:get_ec(), mbedtls.ecdh.THEIRS))
local bin = assert(ecdh:calc_secret(ctr_drbg))
assert(bin == secret_bin)
