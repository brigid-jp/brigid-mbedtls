local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local hash = mbedtls.md()
  :setup(mbedtls.md.SHA256)
  :starts()
  :update(test.sha256.message)
  :finish()
assert(hash == test.sha256.hash)

local hmac = mbedtls.md()
  :setup(mbedtls.md.SHA256, true)
  :hmac_starts(test.sha256.secret)
  :hmac_update(test.sha256.message)
  :hmac_finish()
assert(hmac == test.sha256.hmac)
