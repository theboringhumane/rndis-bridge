// rndis-bridge: userspace RNDIS (Android USB tethering) -> macOS utun bridge.
// Build: make   Run: sudo ./rndis-bridge   (Ctrl-C to tear down)
// Without sudo it only does the USB/RNDIS handshake + DHCP and exits (dry run).
// RNDIS fields are little-endian; this assumes a little-endian host (Apple Silicon / x86).
#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static libusb_device_handle *h;
static int ctrl_if = -1, data_if = -1, out_mps = 512;
static uint8_t ep_in, ep_out, ep_int;
static int tun = -1;
static char ifname[IFNAMSIZ];
static uint8_t my_mac[6], gw_mac[6];
static const uint8_t bcast[6] = {255, 255, 255, 255, 255, 255}, zero_mac[6];
static volatile int have_gw_mac;
static uint32_t my_ip, gw_ip; // network byte order
static volatile sig_atomic_t stop;
static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;

static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t get32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static void die(const char *m) { fprintf(stderr, "rndis-bridge: %s\n", m); exit(1); }

// ---- RNDIS control channel ----
static uint32_t reqid;
static int rndis_cmd(uint8_t *msg, int len, uint8_t *resp, int cap) {
    uint32_t type = get32(msg);
    put32(msg + 8, ++reqid);
    int r = libusb_control_transfer(h, 0x21, 0 /*SEND_ENCAPSULATED_COMMAND*/, 0, ctrl_if, msg, len, 5000);
    if (r < 0) return r;
    for (int i = 0; i < 50; i++) {
        uint8_t note[8]; int got;
        if (ep_int) libusb_interrupt_transfer(h, ep_int, note, sizeof note, &got, 100); // RESPONSE_AVAILABLE
        else usleep(20000);
        r = libusb_control_transfer(h, 0xA1, 1 /*GET_ENCAPSULATED_RESPONSE*/, 0, ctrl_if, resp, cap, 5000);
        if (r >= 16 && get32(resp) == (type | 0x80000000) && get32(resp + 8) == reqid)
            return get32(resp + 12) == 0 ? r : -100;
    }
    return -101;
}

static void rndis_init(void) {
    uint8_t m[64] = {0}, r[1100];
    put32(m, 2); put32(m + 4, 24); put32(m + 12, 1); put32(m + 16, 0); put32(m + 20, 16384); // INITIALIZE
    if (rndis_cmd(m, 24, r, sizeof r) < 0) die("RNDIS INITIALIZE failed");
    memset(m, 0, sizeof m);
    put32(m, 4); put32(m + 4, 28); put32(m + 12, 0x01010101); // QUERY OID_802_3_PERMANENT_ADDRESS
    if (rndis_cmd(m, 28, r, sizeof r) < 0) die("RNDIS QUERY mac failed");
    memcpy(my_mac, r + 8 + get32(r + 20), 6);
    memset(m, 0, sizeof m);
    put32(m, 5); put32(m + 4, 32); put32(m + 12, 0x0001010E); put32(m + 16, 4); put32(m + 20, 20);
    put32(m + 28, 0x1 | 0x2 | 0x8); // SET OID_GEN_CURRENT_PACKET_FILTER: directed|multicast|broadcast
    if (rndis_cmd(m, 32, r, sizeof r) < 0) die("RNDIS SET packet filter failed");
}

// ---- Ethernet over RNDIS_PACKET_MSG ----
static void send_eth(const uint8_t *dst, uint16_t etype, const uint8_t *pl, int plen) {
    uint8_t b[44 + 14 + 1600 + 1];
    if (plen > 1600) return;
    int fl = 14 + plen, tot = 44 + fl, xl = tot, t;
    memset(b, 0, 44);
    put32(b, 1); put32(b + 4, tot); put32(b + 8, 36); put32(b + 12, fl);
    memcpy(b + 44, dst, 6); memcpy(b + 50, my_mac, 6); b[56] = etype >> 8; b[57] = etype & 0xff;
    memcpy(b + 58, pl, plen);
    if (xl % out_mps == 0) b[xl++] = 0; // avoid needing a zero-length packet
    pthread_mutex_lock(&out_lock);
    libusb_bulk_transfer(h, ep_out, b, xl, &t, 1000);
    pthread_mutex_unlock(&out_lock);
}

static void arp_send(int op, const uint8_t *tha, uint32_t tpa, const uint8_t *dst) {
    uint8_t a[28] = {0, 1, 8, 0, 6, 4, 0, (uint8_t)op};
    memcpy(a + 8, my_mac, 6); memcpy(a + 14, &my_ip, 4); memcpy(a + 18, tha, 6); memcpy(a + 24, &tpa, 4);
    send_eth(dst, 0x0806, a, 28);
}

static uint16_t csum(const uint8_t *p, int n) {
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i + 1];
    if (n & 1) s += p[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

// ---- DHCP client (just enough: DISCOVER/OFFER/REQUEST/ACK) ----
static uint32_t dhcp_xid;
static uint8_t dhcp_buf[1600];
static volatile int dhcp_len;

static void dhcp_send(int type, uint32_t req_ip, uint32_t server) {
    uint8_t p[28 + 300] = {0}, *d = p + 28, *o = d + 240;
    d[0] = 1; d[1] = 1; d[2] = 6; memcpy(d + 4, &dhcp_xid, 4); d[10] = 0x80; memcpy(d + 28, my_mac, 6);
    d[236] = 99; d[237] = 130; d[238] = 83; d[239] = 99;
    *o++ = 53; *o++ = 1; *o++ = type;
    if (req_ip) { *o++ = 50; *o++ = 4; memcpy(o, &req_ip, 4); o += 4; }
    if (server) { *o++ = 54; *o++ = 4; memcpy(o, &server, 4); o += 4; }
    *o++ = 55; *o++ = 2; *o++ = 1; *o++ = 3; *o++ = 255;
    p[0] = 0x45; p[2] = sizeof p >> 8; p[3] = sizeof p & 0xff; p[8] = 64; p[9] = 17;
    memset(p + 16, 255, 4);
    uint16_t c = csum(p, 20); p[10] = c >> 8; p[11] = c & 0xff;
    p[21] = 68; p[23] = 67; p[24] = (8 + 300) >> 8; p[25] = (8 + 300) & 0xff;
    send_eth(bcast, 0x0800, p, sizeof p);
}

// Returns DHCP message type of the reply; fills yiaddr/router/server.
static int dhcp_parse(uint32_t *yi, uint32_t *router, uint32_t *server) {
    const uint8_t *ip = dhcp_buf, *d = ip + (ip[0] & 15) * 4 + 8, *end = dhcp_buf + dhcp_len;
    int type = 0;
    if (d + 240 > end || d[0] != 2 || memcmp(d + 4, &dhcp_xid, 4)) return 0;
    memcpy(yi, d + 16, 4);
    for (const uint8_t *o = d + 240; o + 2 <= end && *o != 255;) {
        if (*o == 0) { o++; continue; }
        if (o + 2 + o[1] > end) break;
        if (o[0] == 53) type = o[2];
        if (o[0] == 3 && o[1] >= 4) memcpy(router, o + 2, 4);
        if (o[0] == 54 && o[1] >= 4) memcpy(server, o + 2, 4);
        o += 2 + o[1];
    }
    return type;
}

// ---- receive path ----
static void on_frame(const uint8_t *f, int n) {
    if (n < 14) return;
    uint16_t et = (f[12] << 8) | f[13];
    const uint8_t *p = f + 14;
    n -= 14;
    if (et == 0x0806 && n >= 28) {
        uint32_t spa, tpa; memcpy(&spa, p + 14, 4); memcpy(&tpa, p + 24, 4);
        if (gw_ip && spa == gw_ip) { memcpy(gw_mac, p + 8, 6); have_gw_mac = 1; }
        if (p[7] == 1 && my_ip && tpa == my_ip) arp_send(2, p + 8, spa, p + 8);
    } else if (et == 0x0800 && n >= 20) {
        int hl = (p[0] & 15) * 4;
        if (dhcp_xid && p[9] == 17 && n >= hl + 8 && p[hl + 3] == 68 && p[hl + 2] == 0 && n <= (int)sizeof dhcp_buf) {
            memcpy(dhcp_buf, p, n); memcpy(gw_mac, f + 6, 6); dhcp_len = n;
            return;
        }
        if (my_ip && tun >= 0 && !memcmp(p + 16, &my_ip, 4)) {
            uint8_t b[4 + 1600] = {0, 0, 0, AF_INET};
            if (n > 1600) return;
            memcpy(b + 4, p, n);
            write(tun, b, 4 + n);
        }
    }
}

static void rx_once(int timeout_ms) {
    static uint8_t b[65536];
    int got = 0;
    if (libusb_bulk_transfer(h, ep_in, b, sizeof b, &got, timeout_ms) < 0 && got == 0) return;
    for (int off = 0; off + 44 <= got;) { // one transfer may hold several RNDIS messages
        uint32_t type = get32(b + off), len = get32(b + off + 4);
        if (len < 8 || off + (int)len > got) break;
        if (type == 1) {
            uint32_t doff = get32(b + off + 8), dlen = get32(b + off + 12);
            if (8 + doff + dlen <= len) on_frame(b + off + 8 + doff, dlen);
        }
        off += len;
    }
}

static void *rx_thread(void *_) { while (!stop) rx_once(200); return NULL; }

static void *tx_thread(void *_) {
    uint8_t b[4 + 1600];
    while (!stop) {
        fd_set fs; FD_ZERO(&fs); FD_SET(tun, &fs);
        struct timeval tv = {0, 200000};
        if (select(tun + 1, &fs, NULL, NULL, &tv) <= 0) continue;
        ssize_t n = read(tun, b, sizeof b);
        if (n <= 24 || b[3] != AF_INET) continue; // IPv4 only
        if (!have_gw_mac) { arp_send(1, zero_mac, gw_ip, bcast); continue; }
        send_eth(gw_mac, 0x0800, b + 4, n - 4); // point-to-point: everything goes via the phone
    }
    return NULL;
}

// ---- setup ----
static void find_phone(libusb_context *ctx) {
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(ctx, &list);
    int saw_samsung = 0; // Samsung VID 0x04e8: give a precise hint if tethering is off
    for (ssize_t i = 0; i < cnt && !h; i++) {
        struct libusb_device_descriptor dd;
        struct libusb_config_descriptor *cd;
        if (libusb_get_device_descriptor(list[i], &dd)) continue;
        if (dd.idVendor == 0x04e8) saw_samsung = 1;
        if (libusb_get_active_config_descriptor(list[i], &cd)) continue;
        for (int k = 0; k < cd->bNumInterfaces; k++) {
            const struct libusb_interface_descriptor *a = &cd->interface[k].altsetting[0];
            if ((a->bInterfaceClass == 0xE0 && a->bInterfaceSubClass == 1 && a->bInterfaceProtocol == 3) ||
                (a->bInterfaceClass == 2 && a->bInterfaceSubClass == 2 && a->bInterfaceProtocol == 0xFF)) {
                ctrl_if = a->bInterfaceNumber;
                for (int e = 0; e < a->bNumEndpoints; e++)
                    if ((a->endpoint[e].bmAttributes & 3) == LIBUSB_TRANSFER_TYPE_INTERRUPT) ep_int = a->endpoint[e].bEndpointAddress;
            } else if (a->bInterfaceClass == 0x0A && a->bNumEndpoints >= 2) {
                data_if = a->bInterfaceNumber;
                for (int e = 0; e < a->bNumEndpoints; e++) {
                    const struct libusb_endpoint_descriptor *ep = &a->endpoint[e];
                    if ((ep->bmAttributes & 3) != LIBUSB_TRANSFER_TYPE_BULK) continue;
                    if (ep->bEndpointAddress & 0x80) ep_in = ep->bEndpointAddress;
                    else { ep_out = ep->bEndpointAddress; out_mps = ep->wMaxPacketSize; }
                }
            }
        }
        libusb_free_config_descriptor(cd);
        if (ctrl_if >= 0 && data_if >= 0 && ep_in && ep_out) {
            printf("phone %04x:%04x, ctrl if %d, data if %d, ep in %02x out %02x int %02x\n",
                   dd.idVendor, dd.idProduct, ctrl_if, data_if, ep_in, ep_out, ep_int);
            int r = libusb_open(list[i], &h);
            if (r) { fprintf(stderr, "libusb_open: %s\n", libusb_strerror(r)); exit(1); }
        } else ctrl_if = data_if = -1;
    }
    libusb_free_device_list(list, 1);
    if (!h) {
        if (saw_samsung) die("Samsung phone found but not in USB tethering mode.\n"
                             "  On the phone: Settings > Connections > Mobile Hotspot and Tethering > USB tethering (turn ON).");
        die("no RNDIS device found. Plug in the phone and turn on USB tethering in its settings.");
    }
}

static void dhcp(void) {
    uint32_t yi = 0, router = 0, server = 0;
    arc4random_buf(&dhcp_xid, 4);
    for (int stage = 0, tries = 0; stage < 2 && tries < 8; tries++) {
        dhcp_len = 0;
        if (stage == 0) dhcp_send(1, 0, 0); else dhcp_send(3, yi, server);
        for (int i = 0; i < 15 && !dhcp_len; i++) rx_once(200);
        if (!dhcp_len) continue;
        int t = dhcp_parse(&yi, &router, &server);
        if (stage == 0 && t == 2) stage = 1;          // OFFER -> send REQUEST
        else if (stage == 1 && t == 5) stage = 2;     // ACK
        else if (stage == 1 && t == 6) stage = 0;     // NAK -> restart
        if (stage == 2) { my_ip = yi; gw_ip = router ? router : server; have_gw_mac = 1; }
    }
    dhcp_xid = 0;
    if (!my_ip) {
        fprintf(stderr, "DHCP failed, using static 192.168.42.100 via 192.168.42.129\n");
        my_ip = inet_addr("192.168.42.100"); gw_ip = inet_addr("192.168.42.129");
        arp_send(1, zero_mac, gw_ip, bcast);
    }
}

static void utun_open(void) {
    tun = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    struct ctl_info ci = {0};
    strlcpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof ci.ctl_name);
    if (tun < 0 || ioctl(tun, CTLIOCGINFO, &ci) < 0) die("utun control socket failed");
    struct sockaddr_ctl sc = {.sc_len = sizeof sc, .sc_family = AF_SYSTEM, .ss_sysaddr = AF_SYS_CONTROL, .sc_id = ci.ctl_id, .sc_unit = 0};
    if (connect(tun, (struct sockaddr *)&sc, sizeof sc) < 0) die("utun connect failed");
    socklen_t l = sizeof ifname;
    if (getsockopt(tun, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &l) < 0) die("utun ifname failed");
}

static void sh(const char *fmt, const char *a, const char *b, const char *c) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, fmt, a, b, c);
    printf("+ %s\n", cmd);
    if (system(cmd)) fprintf(stderr, "command failed: %s\n", cmd);
}

static void on_sig(int _) { stop = 1; }

int main(void) {
    libusb_context *ctx;
    if (libusb_init(&ctx)) die("libusb_init failed");
    find_phone(ctx);
    int r;
    if ((r = libusb_claim_interface(h, ctrl_if)) || (r = libusb_claim_interface(h, data_if))) {
        fprintf(stderr, "claim interface: %s\n", libusb_strerror(r));
        return 1;
    }
    rndis_init();
    printf("RNDIS up, host mac %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    dhcp();
    char ips[16], gws[16];
    strlcpy(ips, inet_ntoa(*(struct in_addr *)&my_ip), sizeof ips);
    strlcpy(gws, inet_ntoa(*(struct in_addr *)&gw_ip), sizeof gws);
    printf("IP %s gateway %s (gw mac %s)\n", ips, gws, have_gw_mac ? "known" : "pending ARP");

    if (geteuid() != 0) {
        printf("not root: dry run done (USB + RNDIS + DHCP OK). Run with sudo to bring up utun.\n");
    } else {
        utun_open();
        sh("ifconfig %s inet %s %s netmask 255.255.255.255 mtu 1500 up", ifname, ips, gws);
        // Scoped default: only sockets bound to this interface use it; Wi-Fi stays the system default.
        sh("route -q -n add -ifscope %s default %s", ifname, gws, NULL);
        printf("\n%s is up. Try:  curl --interface %s https://speed.cloudflare.com/cdn-cgi/trace\nCtrl-C to stop.\n", ifname, ifname);
        signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
        pthread_t rt, tt;
        pthread_create(&rt, NULL, rx_thread, NULL);
        pthread_create(&tt, NULL, tx_thread, NULL);
        pthread_join(rt, NULL); pthread_join(tt, NULL);
        printf("\ntearing down %s\n", ifname);
        sh("route -q -n delete -ifscope %s default", ifname, NULL, NULL);
        close(tun); // destroys the utun interface and its addresses
    }
    uint8_t m[12] = {0};
    put32(m, 3); put32(m + 4, 12); put32(m + 8, ++reqid); // RNDIS HALT (no response)
    libusb_control_transfer(h, 0x21, 0, 0, ctrl_if, m, sizeof m, 1000);
    libusb_release_interface(h, data_if);
    libusb_release_interface(h, ctrl_if);
    libusb_close(h);
    libusb_exit(ctx);
    return 0;
}
