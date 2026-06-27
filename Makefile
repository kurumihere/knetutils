CC ?= cc
WARNING_FLAGS = -Wall -Wextra -pedantic -Werror -Wdeclaration-after-statement
STANDARD_FLAGS = -std=c11 -D_GNU_SOURCE
INCLUDES = -I./include

ALL_CFLAGS = $(CFLAGS) $(WARNING_FLAGS) $(STANDARD_FLAGS) $(INCLUDES)

SRCS = src/main.c \
       src/base/cli.c \
       src/base/net.c \
       src/base/utils.c \
       src/arping.c \
       src/ping.c \
       src/sniff.c \
       src/tcping.c \
       src/traceroute.c \
       src/pscan.c

TARGET = bin/knetutils

all: $(TARGET) links

$(TARGET): $(SRCS)
	@mkdir -p bin
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

links: $(TARGET)
	@mkdir -p bin
	@ln -sf knetutils bin/arping
	@ln -sf knetutils bin/ping
	@ln -sf knetutils bin/sniff
	@ln -sf knetutils bin/tcping
	@ln -sf knetutils bin/traceroute
	@ln -sf knetutils bin/pscan

clean:
	rm -f $(TARGET) bin/arping bin/ping bin/sniff bin/tcping bin/traceroute bin/pscan
	rm -rf bin/

analyze: clean
	scan-build $(MAKE) all

format:
	clang-format -i $(SRCS) include/*.h

lint:
	clang-tidy $(SRCS) include/*.h -- $(INCLUDES) $(STANDARD_FLAGS)

test: all
	@echo "Running basic tests..."
	@./tests/test_basic.sh

.PHONY: all links clean analyze format lint test
