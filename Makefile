CXXFLAGS += -Wall -W -std=c++11 $(CFLAGS)
CPPFLAGS += -I$(LUA_INCDIR)
LDFLAGS += $(LIBFLAG)
LDLIBS +=

TARGET = mbedtls.so
OBJS = module.o

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
