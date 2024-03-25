#ifndef BRIGID_MBEDTLS_MPI_HPP
#define BRIGID_MBEDTLS_MPI_HPP

#include "common.hpp"
#include <mbedtls/bignum.h>

namespace brigid {
  class mpi_t : public context<
    mpi_t,
    mbedtls_mpi,
    mbedtls_mpi_init,
    mbedtls_mpi_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.mpi";
  };
}

#endif
