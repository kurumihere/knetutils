CC ?= cc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

WARNING_FLAGS = -Wall -Wextra -pedantic -Werror
STANDARD_FLAGS = -std=c11 -D_GNU_SOURCE
INCLUDES = -I./include

ALL_CFLAGS = $(CFLAGS) $(WARNING_FLAGS) $(STANDARD_FLAGS) $(INCLUDES)

SRCS = src/arping.c \
       src/arping_cli.c \
       src/main.c \
       src/net.c \
       src/ping.c \
       src/ping_cli.c \
       src/tcping.c \
       src/tcping_cli.c \
       src/traceroute.c \
       src/traceroute_cli.c \
       src/utils.c

OBJS = $(SRCS:.c=.o)

TARGET = bin/knetutils

all: $(TARGET) links

$(TARGET): $(OBJS)
	@mkdir -p bin
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

.c.o:
	$(CC) $(ALL_CFLAGS) -c $< -o $@

links: $(TARGET)
	@mkdir -p bin
	@ln -sf knetutils bin/arping
	@ln -sf knetutils bin/ping
	@ln -sf knetutils bin/tcping
	@ln -sf knetutils bin/traceroute

clean:
	rm -f $(OBJS) $(TARGET) bin/arping bin/ping bin/tcping bin/traceroute
	rm -rf bin/

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/knetutils
	ln -sf knetutils $(DESTDIR)$(BINDIR)/arping
	ln -sf knetutils $(DESTDIR)$(BINDIR)/ping
	ln -sf knetutils $(DESTDIR)$(BINDIR)/tcping
	ln -sf knetutils $(DESTDIR)$(BINDIR)/traceroute

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/knetutils
	rm -f $(DESTDIR)$(BINDIR)/arping
	rm -f $(DESTDIR)$(BINDIR)/ping
	rm -f $(DESTDIR)$(BINDIR)/tcping
	rm -f $(DESTDIR)$(BINDIR)/traceroute

analyze: clean
	scan-build $(MAKE) all

format:
	clang-format -i $(SRCS) include/*.h

.PHONY: all links clean install uninstall analyze format

