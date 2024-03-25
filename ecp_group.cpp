#include "common.hpp"
#include "ecp_group.hpp"

namespace brigid {
  namespace {
    using self_t = ecp_group_t;

    void impl_load(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto group_id = static_cast<mbedtls_ecp_group_id>(luaL_checkinteger(L, 2));
      check(mbedtls_ecp_group_load(self->get(), group_id));
    }
  }

  void initialize_ecp_group(lua_State* L) {
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

      set_field(L, -1, "load", function<impl_load>());
    }
    lua_setfield(L, -2, "group");
  }
}
