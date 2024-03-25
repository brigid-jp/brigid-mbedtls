CXXFLAGS += -Wall -W -std=c++11 $(CFLAGS)
CPPFLAGS += -I../mbedtls/include -I$(LUA_INCDIR) -MMD
LDFLAGS += -L../mbedtls/library $(LIBFLAG) 
LDLIBS += -lmbedcrypto

VPATH = ..
TARGET = mbedtls.so
OBJS = \
	common.o \
	base64.o \
	ctr_drbg.o \
	ecdh.o \
	ecdsa.o \
	ecp.o \
	ecp_group.o \
	ecp_keypair.o \
	ecp_point.o \
	entropy.o \
	md.o \
	mpi.o \
	pk.o \
	module.o

all: $(TARGET)

clean:
	rm -f *.d *.o $(TARGET)

install:
	mkdir -p $(LIBDIR)/brigid
	cp $(TARGET) $(LIBDIR)/brigid

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

.cpp.o:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $<

-include *.d
