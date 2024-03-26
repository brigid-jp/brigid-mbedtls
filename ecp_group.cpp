#include "common.hpp"
#include "ecp_group.hpp"

namespace brigid {
  namespace {
    using self_t = ecp_group_t;

    void impl_load(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto grp_id = static_cast<mbedtls_ecp_group_id>(luaL_checkinteger(L, 2));
      check(mbedtls_ecp_group_load(self->get(), grp_id));
    }

    void impl_get_id(lua_State* L) {
      auto* self = self_t::check(L, 1);
      lua_pushinteger(L, self->get()->id);
    }

    void impl_get_curve_info(lua_State* L) {
      auto* self = self_t::check(L, 1);
      if (const auto* curve_info = mbedtls_ecp_curve_info_from_grp_id(self->get()->id)) {
        lua_newtable(L);
        set_field(L, -1, "grp_id", curve_info->grp_id);
        set_field(L, -1, "tls_id", curve_info->tls_id);
        set_field(L, -1, "bit_size", curve_info->bit_size);
        lua_pushstring(L, curve_info->name);
        lua_setfield(L, -2, "name");
      } else {
        lua_pushnil(L);
      }
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
      set_field(L, -1, "get_id", function<impl_get_id>());
      set_field(L, -1, "get_curve_info", function<impl_get_curve_info>());
    }
    lua_setfield(L, -2, "group");
  }
}
