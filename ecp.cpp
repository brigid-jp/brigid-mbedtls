#include "common.hpp"
#include <mbedtls/ecp.h>

namespace brigid {
  void initialize_ecp_group(lua_State*);
  void initialize_ecp_keypair(lua_State*);
  void initialize_ecp_point(lua_State*);

  void initialize_ecp(lua_State* L) {
    lua_newtable(L);
    {
      initialize_ecp_group(L);
      initialize_ecp_keypair(L);
      initialize_ecp_point(L);

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
    }
    lua_setfield(L, -2, "ecp");
  }
}
