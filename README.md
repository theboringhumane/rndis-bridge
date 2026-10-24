# rndis-bridge

Use your Android phone's USB tethering on a Mac, with no kernel extension and no driver.

Android phones share their connection over USB with RNDIS, a Microsoft protocol that macOS has never
supported. Turn on USB tethering, plug the phone in, and nothing happens. rndis-bridge is a single
C program that talks RNDIS to the phone from userspace (through libusb) and gives macOS a normal
`utun` network interface for it.

By default your Wi-Fi stays the main connection and the phone is an extra interface that you pick per
app or per socket, so you can use both at once. For example, a downloader can split one file across
Wi-Fi and the phone. With `--default` the phone becomes the Mac's main connection instead.

- IPv4 (DHCP, lease renewal) and IPv6 (SLAAC from the phone's router advertisements)
- Survives unplugging, toggling tethering, and the phone changing its MAC or IP
- About 290 Mbit/s down over USB 2.0, measured with 8 USB transfers in flight
- Optional launchd daemon that starts at boot and connects whenever the phone is plugged in

## Install

**Homebrew**

```bash
brew install theboringhumane/tap/rndis-bridge
```

**Prebuilt binary** (universal, libusb built in, nothing else to install)

```bash
curl -fsSL https://github.com/theboringhumane/rndis-bridge/releases/latest/download/rndis-bridge-macos-universal.tar.gz | tar xz
sudo mv rndis-bridge /usr/local/bin/
```

If you download it with a browser instead, macOS quarantines it. Clear that with
`xattr -d com.apple.quarantine rndis-bridge`.

**From source**

```bash
brew install libusb pkgconf
make            # links libusb from Homebrew
make static     # or: one self-contained binary
```

## Use

1. Plug the phone in and turn on USB tethering. On Samsung it is under Settings > Connections >
   Mobile Hotspot and Tethering > USB tethering.
2. Start the bridge:

   ```bash
   sudo rndis-bridge
   ```

   It prints the interface it created, such as `utun4`, and writes the name to
   `/var/run/rndis-bridge.if` while it runs. If no phone is connected yet, it waits for one.
3. Send traffic through it:

   ```bash
   curl --interface "$(cat /var/run/rndis-bridge.if)" https://speed.cloudflare.com/cdn-cgi/trace
   ```

   The `ip=` line should show your mobile carrier's address, not your Wi-Fi one.
4. Press Ctrl-C to stop. Routes, the interface and any `--default` settings are removed.

| Command | What it does |
| --- | --- |
| `rndis-bridge` | Dry run without sudo: USB handshake, DHCP and IPv6 check, then exit. Changes nothing. |
| `sudo rndis-bridge` | Phone as an extra interface. Wi-Fi stays the default route. |
| `sudo rndis-bridge --default` | Phone carries all system IPv4 traffic and DNS. Wi-Fi takes over again if the phone goes away or you stop the bridge. |
| `sudo rndis-bridge --install [--default]` | Install as a launchd daemon: starts at boot, waits for the phone, reconnects. Log: `/var/log/rndis-bridge.log`. |
| `sudo rndis-bridge --uninstall` | Remove the daemon. |

With Homebrew you can also run the daemon through `sudo brew services start rndis-bridge`.

## How it works

1. Finds a USB device with an RNDIS control interface (class `E0/01/03` or `02/02/FF`) and its CDC
   data interface, then claims both with libusb.
2. Runs the RNDIS handshake over control transfers: `INITIALIZE`, then a query for the MAC address,
   then the packet filter.
3. Keeps 8 bulk IN transfers queued. Outgoing frames are sent asynchronously, because replies to the
   phone's ARP and neighbor solicitations are sent from inside the receive callback.
4. Gets IPv4 from the phone with a small DHCP client and renews the lease at half its lifetime.
   If DHCP fails it falls back to `192.168.42.100` via `192.168.42.129`. For IPv6 it sends a router
   solicitation and builds an address from the advertised /64 prefix and its own MAC.
5. Opens a `utun` interface and moves packets between it and the phone. It adds a default route
   scoped to the utun (`route add -ifscope utunN default ...`), so only sockets bound to that
   interface use it.
6. With `--default` it publishes the phone as a network service with `OverridePrimary` in
   SystemConfiguration (`scutil`). macOS then moves the default route and DNS to it. Removing the
   keys hands both back to Wi-Fi.

## Limitations

- `--default` moves IPv4 and DNS only. IPv6 through the phone works for sockets bound to the
  interface. macOS does not look up AAAA records unless the main connection has IPv6.
- The utun number can change from run to run. Read it from `/var/run/rndis-bridge.if`.
- Tested on one phone so far: a Samsung (USB ID `04e8:6863`) on macOS 26.5, Apple M2 Pro, USB 2.0.
  Reports from other phones are welcome.
- Apps that can't bind to an interface keep using Wi-Fi unless you use `--default`.

## Troubleshooting

- **"USB tethering is off"**: the phone is connected but tethering is off. Turn it on.
- **"waiting for an RNDIS phone"**: no tethering device found. Try another cable, since some
  cables only carry power.
- **`claim interface` fails**: another program has the phone open, such as Android File Transfer
  or another copy of this bridge (check for the daemon with `sudo launchctl list | grep rndis`).
- **Connected, but DHCP fails and it falls back to a static address**: the phone's tethering is in
  a bad state. Turn USB tethering off and on again.

## License

MIT
