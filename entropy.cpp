#include "common.hpp"
#include "entropy.hpp"

#include <vector>

namespace brigid {
  namespace {
    using self_t = entropy_t;

    void impl_func(lua_State* L) {
      auto* self = static_cast<self_t*>(luaL_checkudata(L, 1, self_t::name));
      const auto size = luaL_checkinteger(L, 2);
      if (size < 0) {
        luaL_argerror(L, 2, "out of bounds");
        return;
      }
      std::vector<unsigned char> buffer(size);
      check(mbedtls_entropy_func(self->get(), buffer.data(), buffer.size()));
      lua_pushlstring(L, reinterpret_cast<const char*>(buffer.data()), buffer.size());
    }
  }

  void initialize_entropy(lua_State* L) {
    lua_newtable(L);
    {
      luaL_newmetatable(L, self_t::name);
      lua_pushvalue(L, -2);
      lua_setfield(L, -2, "__index");
      set_field(L, -1, "__gc", function<self_t::destruct>());
      lua_pop(L, 1);

      lua_newtable(L);
      set_field(L, -1, "__call", function<self_t::construct>());
      lua_setmetatable(L, -2);

      set_field(L, -1, "func", function<impl_func>());
    }
    lua_setfield(L, -2, "entropy");
  }
}
