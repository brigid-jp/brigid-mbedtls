#ifndef BRIGID_MBEDTLS_ECP_GROUP_HPP
#define BRIGID_MBEDTLS_ECP_GROUP_HPP

#include "common.hpp"

#include <mbedtls/ecp.h>

namespace brigid {
  class ecp_group_t : public context<ecp_group_t, mbedtls_ecp_group, mbedtls_ecp_group_init, mbedtls_ecp_group_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.ecp.group";
  };
}

#endif
