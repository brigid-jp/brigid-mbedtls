CXXFLAGS += -Wall -W -std=c++11 $(CFLAGS)
CPPFLAGS += -I../mbedtls/include -I$(LUA_INCDIR) -MMD
LDFLAGS += -L../mbedtls/library $(LIBFLAG) 
LDLIBS += -lmbedcrypto

VPATH = ..
TARGET = mbedtls.so
OBJS = \
	common.o \
	ctr_drbg.o \
	entropy.o \
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