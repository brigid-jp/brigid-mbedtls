export CFLAGS ROCK_CFLAGS ROCK_LIBFLAG ROCK_LUA_INCDIR ROCK_LIBDIR
CFLAGS = -std=c99 $(ROCK_CFLAGS)
DEPEND = mbedtls/library/libmbedcrypto.a

all: $(DEPEND)
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
	touch mbedtls/library/psa_crypto_driver_wrappers.h
	touch mbedtls/library/psa_crypto_driver_wrappers_no_static.c
	$(MAKE) -C mbedtls -j 8 lib
