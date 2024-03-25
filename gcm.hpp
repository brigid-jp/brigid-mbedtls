#ifndef BRIGID_MBEDTLS_GCM_HPP
#define BRIGID_MBEDTLS_GCM_HPP

#include "common.hpp"
#include <mbedtls/gcm.h>

namespace brigid {
  class gcm_t : public context<
    gcm_t,
    mbedtls_gcm_context,
    mbedtls_gcm_init,
    mbedtls_gcm_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.gcm";
  };
}

#endif
