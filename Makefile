export CFLAGS ROCK_CFLAGS ROCK_LIBFLAG ROCK_LUA_INCDIR ROCK_LIBDIR
CFLAGS = -std=c99 -fvisibility=hidden $(ROCK_CFLAGS)
DEPEND = mbedtls/library/libmbedcrypto.a
GIT_CLEAN = git clean -d -e '.*.swp' -x

all: $(DEPEND) base64url.hpp
	$(MAKE) -C brigid -j 8

clean:
	$(MAKE) -C brigid clean

git-clean-dry-run:
	$(GIT_CLEAN) -n
	(cd mbedtls && $(GIT_CLEAN) -n)

git-clean-force:
	$(GIT_CLEAN) -f
	(cd mbedtls && $(GIT_CLEAN) -f)

check:
	./test.sh

install:
	$(MAKE) -C brigid install

archive:
	./archive.sh

$(DEPEND):
	touch mbedtls/library/psa_crypto_driver_wrappers.h
	touch mbedtls/library/psa_crypto_driver_wrappers_no_static.c
	$(MAKE) -C mbedtls -j 8 lib

base64url.hpp: base64url.lua
	./$< >$@
