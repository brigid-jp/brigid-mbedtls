#include "common.hpp"

#include <mbedtls/entropy.h>

#include <vector>

namespace brigid {
  namespace {
    static constexpr const char metaname[] = "brigid.mbedtls.entropy";
    using entropy_t = context<mbedtls_entropy_context, mbedtls_entropy_init, mbedtls_entropy_free>;

    void impl_call(lua_State* L) {
      new_userdata<entropy_t>(L, metaname);
    }

    void impl_gc(lua_State* L) {
      auto* self = static_cast<entropy_t*>(luaL_checkudata(L, 1, metaname));
      self->~entropy_t();
    }

    void impl_func(lua_State* L) {
      auto* self = static_cast<entropy_t*>(luaL_checkudata(L, 1, metaname));
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
      luaL_newmetatable(L, metaname);
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
