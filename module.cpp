#include <lua.hpp>
#include <exception>

#define BRIGID_EXPORT __attribute__ ((visibility ("default")))

namespace brigid {
  void initialize_common(lua_State*);
  void initialize_base64(lua_State*);
  void initialize_base64url(lua_State*);
  void initialize_cipher(lua_State*);
  void initialize_ctr_drbg(lua_State*);
  void initialize_ecdh(lua_State*);
  void initialize_ecdsa(lua_State*);
  void initialize_ecp(lua_State*);
  void initialize_entropy(lua_State*);
  void initialize_gcm(lua_State*);
  void initialize_md(lua_State*);
  void initialize_mpi(lua_State*);
  void initialize_pk(lua_State*);
  void initialize_version(lua_State*);

  void initialize(lua_State* L) {
    initialize_common(L);
    initialize_base64(L);
    initialize_base64url(L);
    initialize_cipher(L);
    initialize_ctr_drbg(L);
    initialize_ecdh(L);
    initialize_ecdsa(L);
    initialize_ecp(L);
    initialize_entropy(L);
    initialize_gcm(L);
    initialize_md(L);
    initialize_mpi(L);
    initialize_pk(L);
    initialize_version(L);
  }
}

extern "C" int BRIGID_EXPORT luaopen_brigid_mbedtls(lua_State* L) {
  auto top = lua_gettop(L);
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
