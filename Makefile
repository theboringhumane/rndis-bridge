rndis-bridge: rndis-bridge.c
	cc -O2 -Wall -o $@ $< $$(pkg-config --cflags --libs libusb-1.0) -lpthread

clean:
	rm -f rndis-bridge
.PHONY: clean
