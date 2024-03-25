#ifndef BRIGID_MBEDTLS_ECP_KEYPAIR_HPP
#define BRIGID_MBEDTLS_ECP_KEYPAIR_HPP

#include "common.hpp"
#include <mbedtls/ecp.h>

namespace brigid {
  class ecp_keypair_t : public context<
    ecp_keypair_t,
    mbedtls_ecp_keypair,
    mbedtls_ecp_keypair_init,
    mbedtls_ecp_keypair_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.ecp.keypair";
  };
}

#endif
