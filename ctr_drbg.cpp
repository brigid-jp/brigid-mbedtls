#include "common.hpp"
#include "entropy.hpp"

#include <mbedtls/ctr_drbg.h>

namespace brigid {
  class ctr_drbg : public context<ctr_drbg, mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_init, mbedtls_ctr_drbg_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.ctr_drbg";
  };

  namespace {
    using self_t = ctr_drbg;

    void impl_call(lua_State* L) {
      new_userdata<self_t>(L, self_t::name);
    }

    void impl_gc(lua_State* L) {
      static_cast<self_t*>(luaL_checkudata(L, 1, self_t::name))->~self_t();
    }

    void impl_seed(lua_State* L) {
      auto* self = static_cast<self_t*>(luaL_checkudata(L, 1, self_t::name));
      auto* that = static_cast<entropy_t*>(luaL_checkudata(L, 2, entropy_t::name));
      check(mbedtls_ctr_drbg_seed(self->get(), mbedtls_entropy_func, that->get(), nullptr, 0));
    }
  }

  void initialize_ctr_drbg(lua_State* L) {
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

      lua_pushcfunction(L, function<impl_seed>::value);
      lua_setfield(L, -2, "seed");
    }
    lua_setfield(L, -2, "ctr_drbg");
  }
}
