CFLAGS ?= -O2 -Wall
LIBUSB_CFLAGS := $(shell pkg-config --cflags libusb-1.0)

rndis-bridge: rndis-bridge.c
	cc $(CFLAGS) -o $@ $< $(LIBUSB_CFLAGS) $(shell pkg-config --libs libusb-1.0)

# Self-contained binary: libusb linked in, no Homebrew needed at runtime.
# For a universal (arm64 + x86_64) build, point LIBUSB_A at a universal libusb-1.0.a and set ARCHS.
LIBUSB_A ?= $(shell pkg-config --variable=libdir libusb-1.0)/libusb-1.0.a
ARCHS ?= $(shell uname -m)
static: rndis-bridge.c
	cc $(CFLAGS) $(foreach a,$(ARCHS),-arch $(a)) -mmacosx-version-min=11.0 -o rndis-bridge $< $(LIBUSB_CFLAGS) $(LIBUSB_A) \
		-framework IOKit -framework CoreFoundation -framework Security

clean:
	rm -f rndis-bridge
.PHONY: static clean
