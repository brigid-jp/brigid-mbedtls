local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

local entropy = mbedtls.entropy()
local ctr_drbg = mbedtls.ctr_drbg():seed(entropy)

do
  local group = mbedtls.ecp.group()
  local result, message = group:load(mbedtls.ecp.DP_NONE)
  if debug then
    print(message)
  end
  assert(not result)
  assert(group:load(mbedtls.ecp.DP_SECP256R1))
end

do
  local keypair = mbedtls.ecp.keypair()
  keypair:gen_key(mbedtls.ecp.DP_SECP256R1, ctr_drbg)

  local pk = mbedtls.pk()
  assert(pk:setup(mbedtls.pk.ECKEY))
  assert(pk:set_ec(keypair))

  local key_pem = assert(pk:write_key_pem())
  local pubkey_pem = assert(pk:write_pubkey_pem())

  if debug then
    io.write(key_pem)
    io.write(pubkey_pem)
  end
end

-- openssl ec -pubout <key.pem >pubkey.pem
local pubkey_pem = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xGMev+n8tdsj7S3yLkWYy84J5DY
bh/cS6zrRM+c1x38WCfd2RMOSDM4EkWx84hiV/HcVV5aLyeQF5pmTEsvoA==
-----END PUBLIC KEY-----
]]

-- openssl pkey -pubin -outform der <pubkey.pem | tail -b 65 | xxd -i -c 8
local pubkey_bin = string.char(
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

do
  local group = mbedtls.ecp.group():load(mbedtls.ecp.DP_SECP256R1)
  local q = mbedtls.ecp.point()
  local result, message = q:read_binary(group, pubkey_bin:sub(2))
  if debug then
    print(message)
  end
  assert(not result)
  assert(q:read_binary(group, pubkey_bin))
  assert(q:write_binary(group) == pubkey_bin)

  local keypair = mbedtls.ecp.keypair()
  assert(keypair:set_group(group))
  assert(keypair:set_public_key(q))
  assert(keypair:get_public_key():write_binary(group) == pubkey_bin)

  local pk = mbedtls.pk()
  assert(pk:setup(mbedtls.pk.ECKEY))
  assert(pk:set_ec(keypair))
  assert(pk:write_pubkey_pem() == pubkey_pem)
end
