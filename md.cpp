#include "common.hpp"
#include "md.hpp"
#include <vector>

namespace brigid {
  namespace {
    using self_t = md_t;

    void impl_setup(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto md_algorithm = static_cast<mbedtls_md_type_t>(luaL_checkinteger(L, 2));
      auto hmac = lua_toboolean(L, 3);
      check(mbedtls_md_setup(self->get(), mbedtls_md_info_from_type(md_algorithm), hmac));
    }

    void impl_starts(lua_State* L) {
      auto* self = self_t::check(L, 1);
      check(mbedtls_md_starts(self->get()));
    }

    void impl_update(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto input = check_string_reference(L, 2);
      check(mbedtls_md_update(self->get(), input.data(), input.size()));
    }

    void impl_finish(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto size = mbedtls_md_get_size(self->get()->MBEDTLS_PRIVATE(md_info));
      std::vector<unsigned char> output(size);
      check(mbedtls_md_finish(self->get(), output.data()));
      push_string_reference(L, output);
    }

    void impl_hmac_starts(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto key = check_string_reference(L, 2);
      check(mbedtls_md_hmac_starts(self->get(), key.data(), key.size()));
    }

    void impl_hmac_update(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto input = check_string_reference(L, 2);
      check(mbedtls_md_hmac_update(self->get(), input.data(), input.size()));
    }

    void impl_hmac_finish(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto size = mbedtls_md_get_size(self->get()->MBEDTLS_PRIVATE(md_info));
      std::vector<unsigned char> output(size);
      check(mbedtls_md_hmac_finish(self->get(), output.data()));
      push_string_reference(L, output);
    }
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

      set_field(L, -1, "setup", function<impl_setup>());
      set_field(L, -1, "starts", function<impl_starts>());
      set_field(L, -1, "update", function<impl_update>());
      set_field(L, -1, "finish", function<impl_finish>());
      set_field(L, -1, "hmac_starts", function<impl_hmac_starts>());
      set_field(L, -1, "hmac_update", function<impl_hmac_update>());
      set_field(L, -1, "hmac_finish", function<impl_hmac_finish>());

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
