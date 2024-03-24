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

    void impl_seed(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* that = entropy_t::check(L, 2);
      check(mbedtls_ctr_drbg_seed(self->get(), mbedtls_entropy_func, that->get(), nullptr, 0));
    }
  }

  void initialize_ctr_drbg(lua_State* L) {
    lua_newtable(L);
    {
      luaL_newmetatable(L, self_t::name);
      lua_pushvalue(L, -2);
      lua_setfield(L, -2, "__index");

      lua_pushcfunction(L, function<self_t::destruct>::value);
      lua_setfield(L, -2, "__gc");

      lua_pop(L, 1);

      lua_newtable(L);
      lua_pushcfunction(L, function<self_t::construct>::value);
      lua_setfield(L, -2, "__call");
      lua_setmetatable(L, -2);

      lua_pushcfunction(L, function<impl_seed>::value);
      lua_setfield(L, -2, "seed");
    }
    lua_setfield(L, -2, "ctr_drbg");
  }
}
