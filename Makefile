PROJECT=router
SOURCES=*.cpp lib/lib.c
LIBRARY=nope
INCPATHS=include
LIBPATHS=.
LDFLAGS=
CFLAGS=-c -Wall -Werror -Wno-error=unused-variable
CC=g++

# Automatic generation of some important lists
OBJECTS=$(SOURCES:.c=.o)
INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Set up the output file names for the different output types
BINARY=$(PROJECT)

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(LIBFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

clean:
	rm -rf *.o lib/lib.o router hosts_output router_*
