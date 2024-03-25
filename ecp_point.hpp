#ifndef BRIGID_MBEDTLS_ECP_POINT_HPP
#define BRIGID_MBEDTLS_ECP_POINT_HPP

#include "common.hpp"
#include <mbedtls/ecp.h>

namespace brigid {
  class ecp_point_t : public context<
    ecp_point_t,
    mbedtls_ecp_point,
    mbedtls_ecp_point_init,
    mbedtls_ecp_point_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.ecp.point";
  };
}

#endif
