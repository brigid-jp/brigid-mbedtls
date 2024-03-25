#include "common.hpp"
#include "gcm.hpp"
#include <vector>

namespace brigid {
  namespace {
    using self_t = gcm_t;

    void impl_starts(lua_State* L) {
      auto* self = self_t::check(L, 1);
      // check(mbedtls_gcm_starts(self->get()));
    }

    void impl_update(lua_State* L) {
      auto* self = self_t::check(L, 1);
      // auto source = check_string_reference(L, 2);
      // check(mbedtls_gcm_update(self->get(), source.data(), source.size()));
    }

    void impl_finish(lua_State* L) {
      auto* self = self_t::check(L, 1);
      // auto size = mbedtls_gcm_get_size(self->get()->MBEDTLS_PRIVATE(gcm_info));
      // std::vector<unsigned char> buffer(size);
      // check(mbedtls_gcm_finish(self->get(), buffer.data()));
      // push_string_reference(L, buffer);
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

      set_field(L, -1, "starts", function<impl_starts>());
      set_field(L, -1, "update", function<impl_update>());
      set_field(L, -1, "finish", function<impl_finish>());
    }
    lua_setfield(L, -2, "gcm");
  }
}
