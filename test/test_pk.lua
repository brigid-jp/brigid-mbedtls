local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

do
  local pk = mbedtls.pk()
  local result, message = pk:setup(-1)
  if debug then
    print(message)
  end
  assert(not result)
  assert(pk:setup(pk.ECKEY))
end

-- openssl ecparam -genkey -name prime256v1 -noout
local key_pem = [[
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII7NAJCFPZZP6aLyblWg2kXD1tfRgPSjAWr8eqpYzKH8oAoGCCqGSM49
AwEHoUQDQgAE8xGMev+n8tdsj7S3yLkWYy84J5DYbh/cS6zrRM+c1x38WCfd2RMO
SDM4EkWx84hiV/HcVV5aLyeQF5pmTEsvoA==
-----END EC PRIVATE KEY-----
]]

-- openssl ec -pubout <key.pem
local pubkey_pem = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xGMev+n8tdsj7S3yLkWYy84J5DY
bh/cS6zrRM+c1x38WCfd2RMOSDM4EkWx84hiV/HcVV5aLyeQF5pmTEsvoA==
-----END PUBLIC KEY-----
]]

local pk = mbedtls.pk()
local entropy = mbedtls.entropy()
local ctr_drbg = mbedtls.ctr_drbg():seed(entropy)
assert(pk:parse_key(key_pem, ctr_drbg))
assert(pk:write_key_pem() == key_pem)
assert(pk:write_pubkey_pem() == pubkey_pem)
