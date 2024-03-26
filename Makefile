export CFLAGS LIBFLAG LUA_INCDIR LIBDIR

all:
	$(MAKE) -j 8 -C mbedtls
	$(MAKE) -j 8 -C brigid

clean:
	$(MAKE) -C brigid clean

check:
	./test.sh

install:
	$(MAKE) -C brigid install
