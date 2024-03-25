#include "common.hpp"
#include "md.hpp"

namespace brigid {
  namespace {
    using self_t = md_t;
  }

  void initialize_md(lua_State* L) {
    lua_newtable(L);
    {
      luaL_newmetatable(L, self_t::name);
      lua_pushvalue(L, -2);
      lua_setfield(L, -2, "__index");
      set_field(L, -1, "__gc", self_t::destructor());
      lua_pop(L, 1);

      lua_newtable(L);
      set_field(L, -1, "__call", self_t::constructor());
      lua_setmetatable(L, -2);

      set_field(L, -1, "NONE", MBEDTLS_MD_NONE);
      set_field(L, -1, "MD5", MBEDTLS_MD_MD5);
      set_field(L, -1, "RIPEMD160", MBEDTLS_MD_RIPEMD160);
      set_field(L, -1, "SHA1", MBEDTLS_MD_SHA1);
      set_field(L, -1, "SHA224", MBEDTLS_MD_SHA224);
      set_field(L, -1, "SHA256", MBEDTLS_MD_SHA256);
      set_field(L, -1, "SHA384", MBEDTLS_MD_SHA384);
      set_field(L, -1, "SHA512", MBEDTLS_MD_SHA512);
      set_field(L, -1, "SHA3_224", MBEDTLS_MD_SHA3_224);
      set_field(L, -1, "SHA3_256", MBEDTLS_MD_SHA3_256);
      set_field(L, -1, "SHA3_384", MBEDTLS_MD_SHA3_384);
      set_field(L, -1, "SHA3_512", MBEDTLS_MD_SHA3_512);
    }
    lua_setfield(L, -2, "md");
  }
}
