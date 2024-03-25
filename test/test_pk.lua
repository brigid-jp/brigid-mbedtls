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
local pem = [[
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKeXFaquwlyZKLfa+SP7M3q1wFdwz+6ISQQSIEOOtFwloAoGCCqGSM49
AwEHoUQDQgAEr7DTr1DLQTI1Fcr9rChEERuW8Eq8d6Y9grAn2v/ZZ5uxcrSsUwxf
onv1V9J1mS5ZteURWe7rFZAco7zuKTWIRA==
-----END EC PRIVATE KEY-----
]]
local pk = mbedtls.pk()
local entropy = mbedtls.entropy()
local ctr_drbg = mbedtls.ctr_drbg():seed(entropy)
assert(pk:parse_key(pem, ctr_drbg))
print(pk:write_key_pem())
