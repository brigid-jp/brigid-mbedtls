export CFLAGS LIBFLAG LUA_INCDIR LIBDIR

all:
	$(MAKE) -C brigid all

clean:
	$(MAKE) -C brigid clean

check:
	./test.sh

install:
	$(MAKE) -C brigid install
