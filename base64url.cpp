#include "common.hpp"

namespace brigid {
  namespace {
    void impl_encode(lua_State* L) {
    }

    void impl_decode(lua_State* L) {
    }
  }

  void initialize_base64url(lua_State* L) {
    lua_newtable(L);
    {
      set_field(L, -1, "encode", function<impl_encode>());
      set_field(L, -1, "decode", function<impl_decode>());
    }
    lua_setfield(L, -2, "base64");
  }
}
