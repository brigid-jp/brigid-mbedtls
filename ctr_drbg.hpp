#ifndef BRIGID_MBEDTLS_CTR_DRBG_HPP
#define BRIGID_MBEDTLS_CTR_DRBG_HPP

#include "common.hpp"
#include <mbedtls/ctr_drbg.h>

namespace brigid {
  class ctr_drbg_t : public context<
    ctr_drbg_t,
    mbedtls_ctr_drbg_context,
    mbedtls_ctr_drbg_init,
    mbedtls_ctr_drbg_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.ctr_drbg";
    thread_reference ref;
  };
}

#endif
