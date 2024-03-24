local mbedtls = require "brigid.mbedtls"

local entropy = mbedtls.entropy()
for i, byte in ipairs { entropy:func(8):byte(1, 8) } do
  io.write(("%02X"):format(byte))
end
io.write "\n"
