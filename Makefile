export CFLAGS LIBFLAG LUA_INCDIR LIBDIR

DEPEND = mbedtls/library/libmbedcrypto.a

all: $(DEPEND)
	$(MAKE) -C brigid -j 8

clean:
	$(MAKE) -C brigid clean

check:
	./test.sh

install:
	$(MAKE) -C brigid install

$(DEPEND):
	$(MAKE) -C mbedtls -j 8 lib

