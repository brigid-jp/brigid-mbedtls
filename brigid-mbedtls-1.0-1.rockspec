package = "brigid-mbedtls"
version = "1.0-1"
source = {
  url = "https://github.com/brigid-jp/brigid/releases/download/v1.0/brigid-mbedtls.tar.gz";
}
description = {
  summary = "Lua bindings for Mbed TLS";
  license = "Apache or GPL";
  homepage = "https://github.com/brigid-jp/brigid-mbedtls/";
  maintainer = "dev@brigid.jp";
}
build = {
  type = "make";
  build_variables = {
    CFLAGS = "$(CFLAGS)";
    LIBFLAG = "$(LIBFLAG)";
    LUA_INCDIR = "$(LUA_INCDIR)";
  };
  install_variables = {
    LIBDIR = "$(LIBDIR)";
  };
}
