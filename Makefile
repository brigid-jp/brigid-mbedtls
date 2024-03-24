all:
	$(MAKE) -e -C brigid all

clean:
	$(MAKE) -e -C brigid clean

check:
	./test.sh

install:
	$(MAKE) -e -C brigid install
