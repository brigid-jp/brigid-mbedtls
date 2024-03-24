#include "common.hpp"
#include "entropy.hpp"

#include <mbedtls/ctr_drbg.h>

#include <vector>

namespace brigid {
  class ctr_drbg_t : public context<ctr_drbg_t, mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_init, mbedtls_ctr_drbg_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.ctr_drbg";
    thread_reference ref;
  };

  namespace {
    using self_t = ctr_drbg_t;

    void impl_seed(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* entropy = entropy_t::check(L, 2);
      check(mbedtls_ctr_drbg_seed(self->get(), mbedtls_entropy_func, entropy->get(), nullptr, 0));

      if (!self->ref) {
        self->ref = thread_reference(L);
      }
      auto* T = self->ref.get();

      lua_pushvalue(L, 2);
      lua_settop(T, 0);
      lua_xmove(L, T, 1);
    }

    void impl_random(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto size = luaL_checkinteger(L, 2);
      if (size < 0) {
        luaL_argerror(L, 2, "out of bounds");
        return;
      }

      std::vector<unsigned char> buffer(size);
      check(mbedtls_ctr_drbg_random(self->get(), buffer.data(), buffer.size()));
      lua_pushlstring(L, reinterpret_cast<const char*>(buffer.data()), buffer.size());
    }
  }

  void initialize_ctr_drbg(lua_State* L) {
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

      set_field(L, -1, "seed", function<impl_seed>());
      set_field(L, -1, "random", function<impl_random>());
    }
    lua_setfield(L, -2, "ctr_drbg");
  }
}
