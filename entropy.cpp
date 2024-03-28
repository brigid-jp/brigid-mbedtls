#include "common.hpp"
#include "entropy.hpp"
#include <vector>

namespace brigid {
  namespace {
    using self_t = entropy_t;

    void impl_get_default(lua_State* L) {
      self_t::get_default(L);
    }

    void impl_func(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto size = luaL_checkinteger(L, 2);
      if (size < 0) {
        luaL_argerror(L, 2, "out of bounds");
        return;
      }
      std::vector<unsigned char> output(size);
      check(mbedtls_entropy_func(self->get(), output.data(), output.size()));
      push_string_reference(L, output);
    }
  }

  // デフォルトインスタンスをスタックに積んでポインタを返す。
  entropy_t* entropy_t::get_default(lua_State* L) {
    static constexpr const char* registry_key = "brigid.mbedtls.entropy.default";

    lua_getfield(L, LUA_REGISTRYINDEX, registry_key);
    if (auto* self = self_t::test(L, -1)) {
      return self;
    }
    lua_pop(L, 1);

    auto* self = self_t::construct(L);
    lua_pushvalue(L, -1);
    lua_setfield(L, LUA_REGISTRYINDEX, registry_key);

    return self;
  }

  void initialize_entropy(lua_State* L) {
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

      set_field(L, -1, "get_default", function<impl_get_default>());
      set_field(L, -1, "func", function<impl_func>());
    }
    lua_setfield(L, -2, "entropy");
  }
}
