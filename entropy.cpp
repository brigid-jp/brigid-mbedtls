#include "common.hpp"
#include "entropy.hpp"

#include <vector>

namespace brigid {
  namespace {
    using self_t = entropy_t;

    void impl_call(lua_State* L) {
      new_userdata<self_t>(L, self_t::name);
    }

    void impl_gc(lua_State* L) {
      static_cast<self_t*>(luaL_checkudata(L, 1, self_t::name))->~self_t();
    }

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

      lua_pushcfunction(L, function<impl_gc>::value);
      lua_setfield(L, -2, "__gc");

      lua_pop(L, 1);

      lua_newtable(L);
      lua_pushcfunction(L, function<impl_call>::value);
      lua_setfield(L, -2, "__call");
      lua_setmetatable(L, -2);

      lua_pushcfunction(L, function<impl_func>::value);
      lua_setfield(L, -2, "func");
    }
    lua_setfield(L, -2, "entropy");
  }
}
