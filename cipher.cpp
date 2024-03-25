#include "common.hpp"
#include <mbedtls/cipher.h>

namespace brigid {
  void initialize_cipher(lua_State* L) {
    lua_newtable(L);
    {
      set_field(L, -1, "ID_NONE", MBEDTLS_CIPHER_ID_NONE);
      set_field(L, -1, "ID_NULL", MBEDTLS_CIPHER_ID_NULL);
      set_field(L, -1, "ID_AES", MBEDTLS_CIPHER_ID_AES);
      set_field(L, -1, "ID_DES", MBEDTLS_CIPHER_ID_DES);
      set_field(L, -1, "ID_3DES", MBEDTLS_CIPHER_ID_3DES);
      set_field(L, -1, "ID_CAMELLIA", MBEDTLS_CIPHER_ID_CAMELLIA);
      set_field(L, -1, "ID_ARIA", MBEDTLS_CIPHER_ID_ARIA);
      set_field(L, -1, "ID_CHACHA20", MBEDTLS_CIPHER_ID_CHACHA20);
    }
    lua_setfield(L, -2, "cipher");
  }
}
