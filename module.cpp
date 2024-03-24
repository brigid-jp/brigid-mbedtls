#include <lua.hpp>

extern "C" int luaopen_brigid_mbedtls(lua_State* L) {
  lua_newtable(L);
  return 1;
}
