#include "common.hpp"
#include "gcm.hpp"
#include <mbedtls/cipher.h>
#include <cstddef>
#include <array>
#include <vector>

namespace brigid {
  namespace {
    using self_t = gcm_t;

    void impl_setkey(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto cipher = static_cast<mbedtls_cipher_id_t>(luaL_checkinteger(L, 2));
      auto key = check_string_reference(L, 3);
      check(mbedtls_gcm_setkey(self->get(), cipher, key.data(), key.size() * 8));
    }

    void impl_starts(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto mode = luaL_checkinteger(L, 2);
      auto iv = check_string_reference(L, 3);
      check(mbedtls_gcm_starts(self->get(), mode, iv.data(), iv.size()));
    }

    void impl_update(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto input = check_string_reference(L, 2);
      std::vector<unsigned char> output(input.size() + 15);
      std::size_t output_size = 0;
      check(mbedtls_gcm_update(
          self->get(),
          input.data(),
          input.size(),
          output.data(),
          output.size(),
          &output_size));
      push_string_reference(L, string_reference(output.data(), output_size));
    }

    void impl_finish(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto tag_size = luaL_checkinteger(L, 2);
      if (tag_size < 0) {
        luaL_argerror(L, 2, "out of bounds");
        return;
      }
      std::array<unsigned char, 15> output;
      std::size_t output_size = 0;
      std::vector<unsigned char> tag(tag_size);
      check(mbedtls_gcm_finish(
          self->get(),
          output.data(),
          output.size(),
          &output_size,
          tag.data(),
          tag.size()));
      push_string_reference(L, string_reference(output.data(), output_size));
      push_string_reference(L, tag);
    }
  }

  void initialize_gcm(lua_State* L) {
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

      set_field(L, -1, "setkey", function<impl_setkey>());
      set_field(L, -1, "starts", function<impl_starts>());
      set_field(L, -1, "update", function<impl_update>());
      set_field(L, -1, "finish", function<impl_finish>());

      set_field(L, -1, "ENCRYPT", MBEDTLS_GCM_ENCRYPT);
      set_field(L, -1, "DECRYPT", MBEDTLS_GCM_DECRYPT);
    }
    lua_setfield(L, -2, "gcm");
  }
}
