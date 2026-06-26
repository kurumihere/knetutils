CC ?= cc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

WARNING_FLAGS = -Wall -Wextra -pedantic -Werror
STANDARD_FLAGS = -std=c11 -D_GNU_SOURCE
INCLUDES = -I./include

ALL_CFLAGS = $(CFLAGS) $(WARNING_FLAGS) $(STANDARD_FLAGS) $(INCLUDES)

SRCS = src/core/main.c \
       src/core/cli.c \
       src/core/net.c \
       src/core/utils.c \
       src/tools/arping/arping.c \
       src/tools/arping/arping_cli.c \
       src/tools/ping/ping.c \
       src/tools/ping/ping_cli.c \
       src/tools/sniff/sniff.c \
       src/tools/sniff/sniff_cli.c \
       src/tools/tcping/tcping.c \
       src/tools/tcping/tcping_cli.c \
       src/tools/traceroute/traceroute.c \
       src/tools/traceroute/traceroute_cli.c \
       src/tools/pscan/pscan.c \
       src/tools/pscan/pscan_cli.c

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
	@ln -sf knetutils bin/sniff
	@ln -sf knetutils bin/tcping
	@ln -sf knetutils bin/traceroute
	@ln -sf knetutils bin/pscan

clean:
	rm -f $(OBJS) $(TARGET) bin/arping bin/ping bin/sniff bin/tcping bin/traceroute bin/pscan
	rm -rf bin/

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/knetutils
	ln -sf knetutils $(DESTDIR)$(BINDIR)/arping
	ln -sf knetutils $(DESTDIR)$(BINDIR)/ping
	ln -sf knetutils $(DESTDIR)$(BINDIR)/sniff
	ln -sf knetutils $(DESTDIR)$(BINDIR)/tcping
	ln -sf knetutils $(DESTDIR)$(BINDIR)/traceroute
	ln -sf knetutils $(DESTDIR)$(BINDIR)/pscan
	install -d $(DESTDIR)$(PREFIX)/share/man/man8
	install -m 644 man/arping.8 $(DESTDIR)$(PREFIX)/share/man/man8/
	install -m 644 man/ping.8 $(DESTDIR)$(PREFIX)/share/man/man8/
	install -m 644 man/sniff.8 $(DESTDIR)$(PREFIX)/share/man/man8/
	install -m 644 man/tcping.8 $(DESTDIR)$(PREFIX)/share/man/man8/
	install -m 644 man/traceroute.8 $(DESTDIR)$(PREFIX)/share/man/man8/
	install -m 644 man/pscan.8 $(DESTDIR)$(PREFIX)/share/man/man8/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/knetutils
	rm -f $(DESTDIR)$(BINDIR)/arping
	rm -f $(DESTDIR)$(BINDIR)/ping
	rm -f $(DESTDIR)$(BINDIR)/sniff
	rm -f $(DESTDIR)$(BINDIR)/tcping
	rm -f $(DESTDIR)$(BINDIR)/traceroute
	rm -f $(DESTDIR)$(BINDIR)/pscan
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/arping.8
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/ping.8
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/sniff.8
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/tcping.8
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/traceroute.8
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/pscan.8

analyze: clean
	scan-build $(MAKE) all

format:
	clang-format -i $(SRCS) include/*.h

lint:
	clang-tidy $(SRCS) include/*.h -- $(INCLUDES) $(STANDARD_FLAGS)

test: all
	@echo "Running basic tests..."
	@./tests/test_basic.sh

.PHONY: all links clean install uninstall analyze format lint test
