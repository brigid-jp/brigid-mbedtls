#include <lua.hpp>

#include <exception>

namespace brigid {
  void initialize_base64(lua_State*);
  void initialize_ctr_drbg(lua_State*);
  void initialize_entropy(lua_State*);

  void initialize(lua_State* L) {
    initialize_base64(L);
    initialize_ctr_drbg(L);
    initialize_entropy(L);
  }
}

extern "C" int luaopen_brigid_mbedtls(lua_State* L) {
  int top = lua_gettop(L);
  try {
    lua_newtable(L);
    brigid::initialize(L);
    return 1;
  } catch (const std::exception& e) {
    lua_settop(L, top);
    return luaL_error(L, "%s", e.what());
  } catch (...) {
    lua_settop(L, top);
    return luaL_error(L, "unknown exception");
  }
}
