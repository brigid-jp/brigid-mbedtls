local mbedtls = require "brigid.mbedtls"

do
  print "block3 start"
  do
    print "block2 start"
    local ctr_drbg = mbedtls.ctr_drbg()
    do
      print "block1a start"
      local entropy = mbedtls.entropy()
      assert(ctr_drbg:seed(entropy))
      collectgarbage()
      collectgarbage()
      print "block1a done"
    end
    do
      print "block1b start"
      assert(ctr_drbg:seed(mbedtls.entropy()))
      collectgarbage()
      collectgarbage()
      print "block1b finish"
    end
    collectgarbage()
    collectgarbage()
    print "block2 finish"
  end
  collectgarbage()
  collectgarbage()
  print "block3 finish"
end
