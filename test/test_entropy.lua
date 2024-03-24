local mbedtls = require "brigid.mbedtls"

local entropy = mbedtls.entropy()
local data = entropy:func(8)
assert(#data == 8)
