#include "common.hpp"
#include <mbedtls/ecp.h>
#include <stdexcept>

namespace brigid {
  namespace {
    void new_curve_info(lua_State* L, const mbedtls_ecp_curve_info* curve_info) {
      if (!curve_info) {
        throw std::runtime_error("curve information not found");
      }
      lua_newtable(L);
      set_field(L, -1, "grp_id", curve_info->grp_id);
      set_field(L, -1, "tls_id", curve_info->tls_id);
      set_field(L, -1, "bit_size", curve_info->bit_size);
      lua_pushstring(L, curve_info->name);
      lua_setfield(L, -2, "name");
    }

    void impl_curve_info_from_grp_id(lua_State* L) {
      auto grp_id = static_cast<mbedtls_ecp_group_id>(luaL_checkinteger(L, 1));
      new_curve_info(L, mbedtls_ecp_curve_info_from_grp_id(grp_id));
    }

    void impl_curve_info_from_tls_id(lua_State* L) {
      auto tls_id = luaL_checkinteger(L, 1);
      new_curve_info(L, mbedtls_ecp_curve_info_from_tls_id(tls_id));
    }

    void impl_curve_info_from_name(lua_State* L) {
      const auto* name = luaL_checkstring(L, 1);
      new_curve_info(L, mbedtls_ecp_curve_info_from_name(name));
    }
  }

  void initialize_ecp_group(lua_State*);
  void initialize_ecp_keypair(lua_State*);
  void initialize_ecp_point(lua_State*);

  void initialize_ecp(lua_State* L) {
    lua_newtable(L);
    {
      set_field(L, -1, "curve_info_from_grp_id", function<impl_curve_info_from_grp_id>());
      set_field(L, -1, "curve_info_from_tls_id", function<impl_curve_info_from_tls_id>());
      set_field(L, -1, "curve_info_from_name", function<impl_curve_info_from_name>());

      set_field(L, -1, "DP_NONE", MBEDTLS_ECP_DP_NONE);
      set_field(L, -1, "DP_SECP192R1", MBEDTLS_ECP_DP_SECP192R1);
      set_field(L, -1, "DP_SECP224R1", MBEDTLS_ECP_DP_SECP224R1);
      set_field(L, -1, "DP_SECP256R1", MBEDTLS_ECP_DP_SECP256R1);
      set_field(L, -1, "DP_SECP384R1", MBEDTLS_ECP_DP_SECP384R1);
      set_field(L, -1, "DP_SECP521R1", MBEDTLS_ECP_DP_SECP521R1);
      set_field(L, -1, "DP_BP256R1", MBEDTLS_ECP_DP_BP256R1);
      set_field(L, -1, "DP_BP384R1", MBEDTLS_ECP_DP_BP384R1);
      set_field(L, -1, "DP_BP512R1", MBEDTLS_ECP_DP_BP512R1);
      set_field(L, -1, "DP_CURVE25519", MBEDTLS_ECP_DP_CURVE25519);
      set_field(L, -1, "DP_SECP192K1", MBEDTLS_ECP_DP_SECP192K1);
      set_field(L, -1, "DP_SECP224K1", MBEDTLS_ECP_DP_SECP224K1);
      set_field(L, -1, "DP_SECP256K1", MBEDTLS_ECP_DP_SECP256K1);
      set_field(L, -1, "DP_CURVE448", MBEDTLS_ECP_DP_CURVE448);

      set_field(L, -1, "PF_UNCOMPRESSED", MBEDTLS_ECP_PF_UNCOMPRESSED);
      set_field(L, -1, "PF_COMPRESSED", MBEDTLS_ECP_PF_COMPRESSED);

      initialize_ecp_group(L);
      initialize_ecp_keypair(L);
      initialize_ecp_point(L);
    }
    lua_setfield(L, -2, "ecp");
  }
}
