CC = gcc
EXECUTABLES = chatClient5 chatServer5 directoryServer5
INCLUDES = $(wildcard *.h)
SOURCES = $(wildcard *.c)
DEPS = $(INCLUDES)
OBJECTS = $(SOURCES:.c=.o)
OBJECTS += $(SOURCES:.c=.dSYM*)
EXTRAS = $(SOURCES:.c=.exe*)
LIBS = -L/usr/lib -lssl -lcrypto
LDFLAGS =
CFLAGS = -g -ggdb -std=c99 \
         -Wuninitialized -Wunused -Wunused-macros -Wunused-variable \
         -Wunused-function -Wunused-but-set-parameter \
         -Wignored-qualifiers -Wshift-negative-value \
         -Wmain -Wreturn-type \
         -Winit-self -Wimplicit-int -Wimplicit-fallthrough \
         -Wparentheses -Wdangling-else -Wfatal-errors \
         -Wreturn-type -Wredundant-decls -Wswitch-default -Wshadow \
         -Wformat=2 -Wformat-nonliteral -Wformat-y2k -Wformat-security
CFLAGS += -I/usr/include/openssl
CFLAGS += -ggdb3

all: nonblock

nonblock: $(EXECUTABLES)

chatClient5: chatClient5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< $(LIBS)

chatServer5: chatServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< $(LIBS)

directoryServer5: directoryServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< $(LIBS)


# Clean up the mess we made
.PHONY: clean
clean:
	@-rm -rf $(OBJECTS) $(EXECUTABLES) $(EXTRAS)
