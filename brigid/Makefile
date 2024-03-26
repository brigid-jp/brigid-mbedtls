CXXFLAGS += -Wall -W -std=c++11 $(ROCK_CFLAGS)
CPPFLAGS += -I../mbedtls/include -I$(ROCK_LUA_INCDIR) -MMD
LDFLAGS += -L../mbedtls/library $(ROCK_LIBFLAG)
LDLIBS += -lmbedcrypto

VPATH = ..
TARGET = mbedtls.so
OBJS = \
	common.o \
	base64.o \
	cipher.o \
	ctr_drbg.o \
	ecdh.o \
	ecdsa.o \
	ecp.o \
	ecp_group.o \
	ecp_keypair.o \
	ecp_point.o \
	entropy.o \
	gcm.o \
	md.o \
	mpi.o \
	pk.o \
	version.o \
	module.o

all: $(TARGET)

clean:
	rm -f *.d *.o $(TARGET)

install:
	mkdir -p $(ROCK_LIBDIR)/brigid
	cp $(TARGET) $(ROCK_LIBDIR)/brigid

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

.cpp.o:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $<

-include *.d
