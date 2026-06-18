# IEC 104 Test Server Makefile
#
# Prerequisites:
#   - lib60870 installed (headers in /usr/local/include, lib in /usr/local/lib)
#   - Or lib60870 source in ./lib60870 directory
#

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lpthread

# Output
TARGET = iec104_test_server
BUILDDIR = build

# Source files
SRCDIR = src
SOURCES = $(SRCDIR)/iec104_test_server.c

# lib60870 paths
LIB60870_DIR ?= ./lib60870/lib60870-C

# Check if lib60870 is installed system-wide
ifneq ($(wildcard /usr/local/include/lib60870/cs104_slave.h),)
    # System installation
    CFLAGS += -I/usr/local/include/lib60870
    LDFLAGS += -L/usr/local/lib -l60870
else ifneq ($(wildcard /usr/include/lib60870/cs104_slave.h),)
    # System installation (alternative path)
    CFLAGS += -I/usr/include/lib60870
    LDFLAGS += -l60870
else ifneq ($(wildcard $(LIB60870_DIR)/src/inc/api/cs104_slave.h),)
    # Local source
    CFLAGS += -I$(LIB60870_DIR)/src/inc/api \
              -I$(LIB60870_DIR)/src/inc/internal \
              -I$(LIB60870_DIR)/src/common/inc \
              -I$(LIB60870_DIR)/src/hal/inc
    LDFLAGS += -L$(LIB60870_DIR)/build -l60870
    LIB60870_LOCAL = 1
else
    $(error lib60870 not found! Run 'make setup' to download and build it)
endif

.PHONY: all clean run setup lib60870

all: $(BUILDDIR)/$(TARGET)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/$(TARGET): $(SOURCES) | $(BUILDDIR)
ifdef LIB60870_LOCAL
	@echo "Using local lib60870 build"
	@if [ ! -f $(LIB60870_DIR)/build/lib60870.a ]; then \
		echo "Building lib60870 first..."; \
		$(MAKE) lib60870; \
	fi
endif
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@echo "Build complete: $@"

lib60870:
	@echo "Building lib60870..."
	@if [ ! -d "$(LIB60870_DIR)" ]; then \
		echo "Cloning lib60870..."; \
		git clone https://github.com/mz-automation/lib60870.git; \
	fi
	@mkdir -p $(LIB60870_DIR)/build
	@cd $(LIB60870_DIR)/build && cmake .. && make
	@echo "lib60870 built successfully"

setup: lib60870
	@echo "Setup complete!"

run: $(BUILDDIR)/$(TARGET)
	@echo "Starting IEC 104 test server..."
	@cd $(BUILDDIR) && ./$(TARGET)

run-verbose: $(BUILDDIR)/$(TARGET)
	@echo "Starting IEC 104 test server (verbose)..."
	@cd $(BUILDDIR) && ./$(TARGET) --verbose

clean:
	rm -rf $(BUILDDIR)

distclean: clean
	rm -rf lib60870

install: $(BUILDDIR)/$(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(BUILDDIR)/$(TARGET) $(DESTDIR)/usr/local/bin/
	install -d $(DESTDIR)/usr/local/share/iec104_testbed/data
	install -m 644 data/* $(DESTDIR)/usr/local/share/iec104_testbed/data/

help:
	@echo "IEC 104 Test Server Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build the test server (default)"
	@echo "  setup        Download and build lib60870"
	@echo "  lib60870     Build lib60870 only"
	@echo "  run          Build and run the server"
	@echo "  run-verbose  Build and run with verbose output"
	@echo "  clean        Remove build files"
	@echo "  distclean    Remove build files and lib60870"
	@echo "  install      Install to system"
	@echo "  help         Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  LIB60870_DIR  Path to lib60870 source (default: ./lib60870/lib60870-C)"
