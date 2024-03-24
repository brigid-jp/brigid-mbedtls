CXXFLAGS += -Wall -W -std=c++11 $(CFLAGS)
CPPFLAGS += -Imbedtls/include -I$(LUA_INCDIR)
LDFLAGS += -Lmbedtls/library $(LIBFLAG)
LDLIBS += -lmbedcrypto

TARGET = mbedtls.so
OBJS = \
	ctr_drbg.o \
	entropy.o \
	module.o

all: $(TARGET)

clean:
	rm -f *.o $(TARGET)

check:
	./test.sh

install:
	mkdir -p $(LIBDIR)/brigid
	cp $(TARGET) $(LIBDIR)/brigid

mbedtls.so: $(OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

.cpp.o:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $<
