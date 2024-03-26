export CFLAGS LIBFLAG LUA_INCDIR LIBDIR

all:
	$(MAKE) -C mbedtls -j 8 no_test
	$(MAKE) -C brigid -j 8 all

clean:
	$(MAKE) -C brigid clean

check:
	./test.sh

install:
	$(MAKE) -C brigid install
