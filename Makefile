export CFLAGS ROCK_CFLAGS ROCK_LIBFLAG ROCK_LUA_INCDIR ROCK_LIBDIR
CFLAGS = -std=c99 $(ROCK_CFLAGS)
DEPEND = mbedtls/library/libmbedcrypto.a

all: $(DEPEND) base64url.hpp
	$(MAKE) -C brigid -j 8

clean:
	$(MAKE) -C brigid clean

check:
	./test.sh

install:
	$(MAKE) -C brigid install

archive:
	./archive.sh

$(DEPEND):
	$(MAKE) -C mbedtls -j 8 lib

base64url.hpp: base64url.lua
	./$< >$@
