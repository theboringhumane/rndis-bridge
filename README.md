# rndis-bridge

Use your Android phone's USB tethering on a Mac, with no kernel extension and no driver.

Android phones share their connection over USB with RNDIS, a Microsoft protocol that macOS has never
supported. Turn on USB tethering, plug the phone in, and nothing happens. rndis-bridge is a single
C program that talks RNDIS to the phone from userspace (through libusb) and gives macOS a normal
`utun` network interface for it.

Your Wi-Fi stays the default route. The phone's link is added as a separate interface that you pick
per app or per socket, so you can use both at once. For example, a downloader can split one file
across Wi-Fi and the phone.

## Requirements

- macOS on Apple Silicon or Intel (tested on macOS 26.5, M2 Pro)
- Homebrew `libusb` and `pkg-config`
- An Android phone that tethers over RNDIS (most do)

## Build

```bash
brew install libusb pkg-config
make
```

## Run

1. Plug the phone in and turn on USB tethering. On Samsung it is under Settings > Connections >
   Mobile Hotspot and Tethering > USB tethering.
2. Start the bridge:

   ```bash
   sudo ./rndis-bridge
   ```

   It prints the interface it created, such as `utun4`.
3. Send traffic through it:

   ```bash
   curl --interface utun4 https://speed.cloudflare.com/cdn-cgi/trace
   ```

   The `ip=` line should show your mobile carrier's address, not your Wi-Fi one.
4. Press Ctrl-C to stop. The route and the interface are removed and the phone is told to halt.

Run it without `sudo` for a dry run. It does the USB handshake and gets an address over DHCP, then
exits without touching your network settings. This is a quick way to check that your phone works.

## How it works

1. Finds a USB device with an RNDIS control interface (class `E0/01/03` or `02/02/FF`) and its CDC
   data interface, then claims both with libusb.
2. Runs the RNDIS handshake over control transfers: `INITIALIZE`, then a query for the MAC address,
   then the packet filter.
3. Gets an IP and gateway from the phone with a small DHCP client. If DHCP fails it falls back to
   `192.168.42.100` via `192.168.42.129`.
4. Opens a `utun` interface. Outgoing IPv4 packets get an Ethernet header addressed to the phone and
   are sent over bulk OUT. Incoming frames are unwrapped and written back to the utun. It answers
   the phone's ARP requests itself.
5. Adds a default route scoped to the utun (`route add -ifscope utunN default <gateway>`). Only
   sockets bound to that interface use it.

## Limitations

- IPv4 only.
- The utun number can change from run to run. Use the name the program prints.
- Tested on one phone so far: a Samsung (USB ID `04e8:6863`) on USB 2.0, at about 130 Mbit/s.
  Reports from other phones are welcome.
- Apps that can't bind to an interface keep using Wi-Fi. That's on purpose.

## Troubleshooting

- **"not in USB tethering mode"**: the phone is connected but tethering is off. Turn it on.
  Changing the USB mode to "file transfer" doesn't help.
- **"no RNDIS device found"**: try another cable. Some cables only carry power.
- **`claim interface` fails**: another program has the phone open, such as Android File Transfer
  or a running copy of this bridge. Quit it and try again.

## License

MIT
