local mbedtls = require "brigid.mbedtls"

local entropy = mbedtls.entropy()
local ctr_drbg = mbedtls.ctr_drbg()
assert(ctr_drbg:seed(entropy))
print(ctr_drbg)
