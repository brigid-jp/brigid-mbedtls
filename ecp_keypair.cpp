#include "common.hpp"
#include "ecp_keypair.hpp"

namespace brigid {
  namespace {
    using self_t = ecp_keypair_t;
  }

  void initialize_ecp_keypair(lua_State* L) {
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
    }
    lua_setfield(L, -2, "keypair");
  }
}
