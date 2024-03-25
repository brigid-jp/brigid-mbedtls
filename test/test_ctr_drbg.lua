local mbedtls = require "brigid.mbedtls"

local ctr_drbg = mbedtls.ctr_drbg()
ctr_drbg:seed(mbedtls.entropy())
collectgarbage()
collectgarbage()
local data = ctr_drbg:random(8)
assert(#data == 8)
