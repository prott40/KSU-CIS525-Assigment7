#
# Makefile for non-blocking I/O chat server
#
CC	= gcc
EXECUTABLES=chatClient5 chatServer5 directoryServer5
INCLUDES	= $(wildcard *.h)
SOURCES	= $(wildcard *.c)
DEPS		= $(INCLUDES)
OBJECTS	= $(SOURCES:.c=.o)
OBJECTS	+= $(SOURCES:.c=.dSYM*)
EXTRAS	= $(SOURCES:.c=.exe*)
LIBS		=
LDFLAGS	=
CFLAGS	= -g -ggdb -std=c99 \
				-Wuninitialized -Wunused -Wunused-macros -Wunused-variable \
				-Wunused-function -Wunused-but-set-parameter \
				-Wignored-qualifiers -Wshift-negative-value \
				-Wmain -Wreturn-type \
				-Winit-self -Wimplicit-int -Wimplicit-fallthrough \
				-Wparentheses -Wdangling-else -Wfatal-errors \
				-Wreturn-type -Wredundant-decls -Wswitch-default -Wshadow \
				-Wformat=2 -Wformat-nonliteral -Wformat-y2k -Wformat-security
CFLAGS	+= -ggdb3
#CFLAGS	+= -Wconversion
#CFLAGS	+= -Wc99-c11-compat -Wmaybe-uninitialized \
					-Wformat-truncation=2 -Wstringop-truncation \
					-Wformat-overflow=2 -Wformat-signedness

all:	nonblock

nonblock: $(EXECUTABLES)


chatClient4: chatClient4.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<

chatServer4: chatServer4.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<


# Clean up the mess we made
.PHONY: clean
clean:
	@-rm -rf $(OBJECTS) $(EXECUTABLES) $(EXTRAS)
