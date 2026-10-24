// rndis-bridge: userspace RNDIS (Android USB tethering) -> macOS utun bridge.
// Usage: see usage() below. Without sudo it does a dry run (USB + RNDIS + DHCP) and exits.
// RNDIS fields are little-endian; this assumes a little-endian host (Apple Silicon / x86).
#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define VERSION "0.2.0"
#define NRX 8            // bulk IN transfers kept in flight (one at a time caps USB throughput)
#define RX_SIZE 16384    // per transfer; also advertised to the phone as our max transfer size
#define LABEL "dev.theboringhumane.rndis-bridge"
#define PLIST "/Library/LaunchDaemons/" LABEL ".plist"
#define IFFILE "/var/run/rndis-bridge.if" // holds the utun name while running, for scripts
#define SCKEY "State:/Network/Service/rndis-bridge"

static libusb_context *ctx;
static libusb_device_handle *h;
static int ctrl_if, data_if, out_mps;
static uint8_t ep_in, ep_out, ep_int;
static int tun = -1, default_mode;
static char ifname[IFNAMSIZ];
static uint8_t my_mac[6], gw_mac[6], gw6_mac[6];
static const uint8_t bcast[6] = {255, 255, 255, 255, 255, 255}, zero_mac[6];
static uint32_t my_ip, gw_ip, dns_ip, lease_secs; // addresses in network byte order
static uint8_t ll6[16], my_ip6[16], gw6[16];      // written by the RX thread under v6_lock
static volatile int have_gw_mac, link_down, session_end;
static volatile sig_atomic_t stop;
static pthread_mutex_t v6_lock = PTHREAD_MUTEX_INITIALIZER;

static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t get32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static void die(const char *m) { fprintf(stderr, "rndis-bridge: %s\n", m); exit(1); }
static void say(const char *m) { // print a status line only when it changes (we retry in a loop)
    static char last[256];
    if (strcmp(last, m)) { strlcpy(last, m, sizeof last); fprintf(stderr, "%s\n", m); }
}
static int sh(const char *fmt, ...) {
    char cmd[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(cmd, sizeof cmd, fmt, ap); va_end(ap);
    printf("+ %s\n", cmd);
    int r = system(cmd);
    if (r) fprintf(stderr, "command failed: %s\n", cmd);
    return r;
}
static const char *ip4s(uint32_t a, char *b) { return inet_ntop(AF_INET, &a, b, 16); }
static const char *ip6s(const uint8_t *a, char *b) { return inet_ntop(AF_INET6, a, b, INET6_ADDRSTRLEN); }

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

static int rndis_init(void) {
    uint8_t m[64] = {0}, r[1100];
    put32(m, 2); put32(m + 4, 24); put32(m + 12, 1); put32(m + 16, 0); put32(m + 20, RX_SIZE); // INITIALIZE
    if (rndis_cmd(m, 24, r, sizeof r) < 0) return -1;
    memset(m, 0, sizeof m);
    put32(m, 4); put32(m + 4, 28); put32(m + 12, 0x01010101); // QUERY OID_802_3_PERMANENT_ADDRESS
    if (rndis_cmd(m, 28, r, sizeof r) < 0) return -1;
    memcpy(my_mac, r + 8 + get32(r + 20), 6);
    memset(m, 0, sizeof m);
    put32(m, 5); put32(m + 4, 32); put32(m + 12, 0x0001010E); put32(m + 16, 4); put32(m + 20, 20);
    put32(m + 28, 0x1 | 0x2 | 0x4 | 0x8); // SET packet filter: directed|multicast|all-multicast|broadcast
    if (rndis_cmd(m, 32, r, sizeof r) < 0) return -1;
    static const uint8_t ll[8] = {0xfe, 0x80}; // link-local fe80::EUI-64(mac)
    uint8_t a[16];
    memcpy(a, ll, 8);
    a[8] = my_mac[0] ^ 2; a[9] = my_mac[1]; a[10] = my_mac[2]; a[11] = 0xff;
    a[12] = 0xfe; a[13] = my_mac[3]; a[14] = my_mac[4]; a[15] = my_mac[5];
    memcpy(ll6, a, 16);
    return 0;
}

// ---- Ethernet over RNDIS_PACKET_MSG ----
// Sends are async: they also happen inside RX callbacks (ARP/ND replies), where a blocking
// libusb call would deadlock the event thread.
#define TX_MAX 64 // OUT transfers in flight before tx_loop waits
static int tx_inflight; // atomic

static void LIBUSB_CALL tx_cb(struct libusb_transfer *t) {
    if (t->status == LIBUSB_TRANSFER_NO_DEVICE || t->status == LIBUSB_TRANSFER_ERROR) link_down = 1;
    __atomic_sub_fetch(&tx_inflight, 1, __ATOMIC_RELEASE);
}

static void send_eth(const uint8_t *dst, uint16_t etype, const uint8_t *pl, int plen) {
    if (plen > 1600 || link_down) return;
    int fl = 14 + plen, tot = 44 + fl, xl = tot;
    uint8_t *b = calloc(1, tot + 1);
    struct libusb_transfer *t = libusb_alloc_transfer(0);
    if (!b || !t) { free(b); libusb_free_transfer(t); return; }
    put32(b, 1); put32(b + 4, tot); put32(b + 8, 36); put32(b + 12, fl);
    memcpy(b + 44, dst, 6); memcpy(b + 50, my_mac, 6); b[56] = etype >> 8; b[57] = etype & 0xff;
    memcpy(b + 58, pl, plen);
    if (xl % out_mps == 0) xl++; // trailing zero byte: avoids needing a zero-length packet
    libusb_fill_bulk_transfer(t, h, ep_out, b, xl, tx_cb, NULL, 1000);
    t->flags = LIBUSB_TRANSFER_FREE_BUFFER | LIBUSB_TRANSFER_FREE_TRANSFER;
    __atomic_add_fetch(&tx_inflight, 1, __ATOMIC_ACQUIRE);
    if (libusb_submit_transfer(t)) { __atomic_sub_fetch(&tx_inflight, 1, __ATOMIC_RELEASE); link_down = 1; libusb_free_transfer(t); }
}

static void arp_send(int op, const uint8_t *tha, uint32_t tpa, const uint8_t *dst) {
    uint8_t a[28] = {0, 1, 8, 0, 6, 4, 0, (uint8_t)op};
    memcpy(a + 8, my_mac, 6); memcpy(a + 14, &my_ip, 4); memcpy(a + 18, tha, 6); memcpy(a + 24, &tpa, 4);
    send_eth(dst, 0x0806, a, 28);
}

static uint32_t sum16(uint32_t s, const uint8_t *p, int n) {
    for (int i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i + 1];
    if (n & 1) s += p[n - 1] << 8;
    return s;
}
static uint16_t fold(uint32_t s) {
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

// ---- IPv6: router solicitation, SLAAC from RAs, neighbor advertisements ----
static void icmp6_send(const uint8_t *dmac, const uint8_t *dst, uint8_t *ic, int n) {
    uint8_t p[40 + 64] = {0x60}, ph[8] = {0, 0, n >> 8, n & 0xff, 0, 0, 0, 58};
    p[4] = n >> 8; p[5] = n & 0xff; p[6] = 58; p[7] = 255;
    memcpy(p + 8, ll6, 16); memcpy(p + 24, dst, 16);
    ic[2] = ic[3] = 0;
    uint16_t c = fold(sum16(sum16(sum16(0, p + 8, 32), ph, 8), ic, n));
    ic[2] = c >> 8; ic[3] = c & 0xff;
    memcpy(p + 40, ic, n);
    send_eth(dmac, 0x86DD, p, 40 + n);
}

static void rs_send(void) {
    static const uint8_t all_routers[16] = {0xff, 2, [15] = 2}, mac[6] = {0x33, 0x33, 0, 0, 0, 2};
    uint8_t ic[16] = {133, 0, 0, 0, 0, 0, 0, 0, 1, 1};
    memcpy(ic + 10, my_mac, 6);
    icmp6_send(mac, all_routers, ic, sizeof ic);
}

static void on_ra(const uint8_t *smac, const uint8_t *src, const uint8_t *o, int n) {
    for (; n >= 8 && o[1] && o[1] * 8 <= n; n -= o[1] * 8, o += o[1] * 8) {
        // Prefix Information, /64, autonomous flag: address = prefix + our EUI-64.
        // ponytail: ignores lifetimes/withdrawn prefixes; the next RA or reconnect fixes it.
        if (o[0] != 3 || o[1] != 4 || o[2] != 64 || !(o[3] & 0x40)) continue;
        pthread_mutex_lock(&v6_lock);
        memcpy(my_ip6, o + 16, 8); memcpy(my_ip6 + 8, ll6 + 8, 8);
        memcpy(gw6, src, 16); memcpy(gw6_mac, smac, 6);
        pthread_mutex_unlock(&v6_lock);
    }
}

// ---- DHCP client (DISCOVER/OFFER/REQUEST/ACK, plus renew) ----
struct lease { uint32_t yi, router, server, dns, secs; };
static uint32_t dhcp_xid;
static uint8_t dhcp_buf[1600];
static int dhcp_len; // atomic: RX thread fills the slot, DHCP code empties it

static void dhcp_send(int type, uint32_t req_ip, uint32_t server, uint32_t ciaddr) {
    uint8_t p[28 + 300] = {0}, *d = p + 28, *o = d + 240;
    d[0] = 1; d[1] = 1; d[2] = 6; memcpy(d + 4, &dhcp_xid, 4); d[10] = 0x80; memcpy(d + 12, &ciaddr, 4);
    memcpy(d + 28, my_mac, 6);
    d[236] = 99; d[237] = 130; d[238] = 83; d[239] = 99;
    *o++ = 53; *o++ = 1; *o++ = type;
    if (req_ip) { *o++ = 50; *o++ = 4; memcpy(o, &req_ip, 4); o += 4; }
    if (server) { *o++ = 54; *o++ = 4; memcpy(o, &server, 4); o += 4; }
    *o++ = 55; *o++ = 4; *o++ = 1; *o++ = 3; *o++ = 6; *o++ = 51; *o++ = 255;
    p[0] = 0x45; p[2] = sizeof p >> 8; p[3] = sizeof p & 0xff; p[8] = 64; p[9] = 17;
    memcpy(p + 12, &ciaddr, 4); memset(p + 16, 255, 4);
    uint16_t c = fold(sum16(0, p, 20)); p[10] = c >> 8; p[11] = c & 0xff;
    p[21] = 68; p[23] = 67; p[24] = (8 + 300) >> 8; p[25] = (8 + 300) & 0xff;
    send_eth(bcast, 0x0800, p, sizeof p);
}

static int dhcp_parse(struct lease *l) {
    const uint8_t *d = dhcp_buf + (dhcp_buf[0] & 15) * 4 + 8, *end = dhcp_buf + dhcp_len;
    int type = 0;
    if (d + 240 > end || d[0] != 2 || memcmp(d + 4, &dhcp_xid, 4)) return 0;
    memset(l, 0, sizeof *l);
    memcpy(&l->yi, d + 16, 4);
    for (const uint8_t *o = d + 240; o + 2 <= end && *o != 255;) {
        if (*o == 0) { o++; continue; }
        if (o + 2 + o[1] > end) break;
        if (o[0] == 53) type = o[2];
        if (o[1] >= 4) {
            if (o[0] == 3) memcpy(&l->router, o + 2, 4);
            if (o[0] == 6) memcpy(&l->dns, o + 2, 4);
            if (o[0] == 54) memcpy(&l->server, o + 2, 4);
            if (o[0] == 51) { memcpy(&l->secs, o + 2, 4); l->secs = ntohl(l->secs); }
        }
        o += 2 + o[1];
    }
    return type;
}

// Sends one message and waits up to 3 s for a reply with our xid. Returns the reply type or 0.
static int dhcp_exchange(int type, uint32_t req, uint32_t srv, uint32_t ci, struct lease *l) {
    __atomic_store_n(&dhcp_len, 0, __ATOMIC_RELEASE);
    dhcp_send(type, req, srv, ci);
    for (int i = 0; i < 60 && !stop && !link_down; i++) {
        usleep(50000);
        if (!__atomic_load_n(&dhcp_len, __ATOMIC_ACQUIRE)) continue;
        int t = dhcp_parse(l);
        if (t) return t;
        __atomic_store_n(&dhcp_len, 0, __ATOMIC_RELEASE);
    }
    return 0;
}

static int dhcp(void) {
    struct lease l;
    arc4random_buf(&dhcp_xid, 4);
    for (int tries = 0; tries < 4 && !stop && !link_down; tries++) {
        if (dhcp_exchange(1, 0, 0, 0, &l) != 2) continue;           // DISCOVER -> OFFER
        if (dhcp_exchange(3, l.yi, l.server, 0, &l) != 5) continue; // REQUEST -> ACK
        my_ip = l.yi; gw_ip = l.router ? l.router : l.server;
        dns_ip = l.dns ? l.dns : gw_ip; lease_secs = l.secs ? l.secs : 3600;
        have_gw_mac = 1; // gw_mac was taken from the reply's Ethernet source
        dhcp_xid = 0;
        return 1;
    }
    dhcp_xid = 0;
    return 0;
}

// 1 = renewed, 0 = no answer (retry later), -1 = NAK or new address (reconnect from scratch).
static int dhcp_renew(void) {
    struct lease l;
    arc4random_buf(&dhcp_xid, 4);
    int t = dhcp_exchange(3, 0, 0, my_ip, &l);
    dhcp_xid = 0;
    if (t == 5 && l.yi == my_ip) { if (l.secs) lease_secs = l.secs; return 1; }
    return t ? -1 : 0;
}

// ---- receive path ----
static void tun_write(int af, const uint8_t *p, int n) {
    uint8_t b[4 + 1600] = {0, 0, 0, (uint8_t)af};
    if (tun < 0 || n > 1600) return;
    memcpy(b + 4, p, n);
    write(tun, b, 4 + n);
}

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
        if (dhcp_xid && p[9] == 17 && n >= hl + 8 && p[hl + 2] == 0 && p[hl + 3] == 68 && n <= (int)sizeof dhcp_buf &&
            !__atomic_load_n(&dhcp_len, __ATOMIC_ACQUIRE)) {
            memcpy(dhcp_buf, p, n); memcpy(gw_mac, f + 6, 6);
            __atomic_store_n(&dhcp_len, n, __ATOMIC_RELEASE);
            return;
        }
        if (my_ip && !memcmp(p + 16, &my_ip, 4)) tun_write(AF_INET, p, n);
    } else if (et == 0x86DD && n >= 40) {
        int plen = (p[4] << 8) | p[5];
        const uint8_t *src = p + 8, *dst = p + 24, *ic = p + 40;
        if (40 + plen > n) return;
        if (p[6] == 58 && plen >= 8) {
            if (ic[0] == 134 && plen >= 16) { on_ra(f + 6, src, ic + 16, plen - 16); return; }
            if (ic[0] == 135 && plen >= 24) { // Neighbor Solicitation for one of our addresses -> advertise
                static const uint8_t unspec[16];
                if (memcmp(src, unspec, 16) && (!memcmp(ic + 8, ll6, 16) || (my_ip6[0] && !memcmp(ic + 8, my_ip6, 16)))) {
                    uint8_t na[32] = {136, 0, 0, 0, 0x60};
                    memcpy(na + 8, ic + 8, 16); na[24] = 2; na[25] = 1; memcpy(na + 26, my_mac, 6);
                    icmp6_send(f + 6, src, na, sizeof na);
                }
                return;
            }
            if (ic[0] == 133 || ic[0] == 136) return;
        }
        if (my_ip6[0] && !memcmp(dst, my_ip6, 16)) tun_write(AF_INET6, p, 40 + plen);
    }
}

static void on_rndis(const uint8_t *b, int got) {
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

static struct libusb_transfer *rx_xfer[NRX];
static uint8_t rx_buf[NRX][RX_SIZE];
static int rx_pending; // only touched on the event thread once it runs
static pthread_t ev_thread;

static void LIBUSB_CALL rx_cb(struct libusb_transfer *t) {
    if (t->status == LIBUSB_TRANSFER_COMPLETED) on_rndis(t->buffer, t->actual_length);
    else if (t->status != LIBUSB_TRANSFER_CANCELLED && t->status != LIBUSB_TRANSFER_OVERFLOW) link_down = 1;
    if (t->status != LIBUSB_TRANSFER_CANCELLED && !link_down && !session_end && !libusb_submit_transfer(t)) return;
    rx_pending--;
}

static void *ev_loop(void *_) {
    while (rx_pending > 0 || __atomic_load_n(&tx_inflight, __ATOMIC_ACQUIRE) > 0) {
        struct timeval tv = {0, 200000};
        libusb_handle_events_timeout_completed(ctx, &tv, NULL);
    }
    return NULL;
}

static void rx_start(void) {
    rx_pending = 0;
    for (int i = 0; i < NRX; i++) {
        rx_xfer[i] = libusb_alloc_transfer(0);
        libusb_fill_bulk_transfer(rx_xfer[i], h, ep_in, rx_buf[i], RX_SIZE, rx_cb, NULL, 0);
        if (!libusb_submit_transfer(rx_xfer[i])) rx_pending++;
    }
    pthread_create(&ev_thread, NULL, ev_loop, NULL);
}

static void *tx_loop(void *_) {
    uint8_t b[4 + 1600];
    while (!stop && !link_down && !session_end) {
        fd_set fs; FD_ZERO(&fs); FD_SET(tun, &fs);
        struct timeval tv = {0, 200000};
        if (select(tun + 1, &fs, NULL, NULL, &tv) <= 0) continue;
        while (__atomic_load_n(&tx_inflight, __ATOMIC_ACQUIRE) >= TX_MAX && !link_down) usleep(100);
        ssize_t n = read(tun, b, sizeof b);
        if (n <= 24) continue;
        if (b[3] == AF_INET) {
            if (!have_gw_mac) { arp_send(1, zero_mac, gw_ip, bcast); continue; }
            send_eth(gw_mac, 0x0800, b + 4, n - 4); // point-to-point: everything goes via the phone
        } else if (b[3] == AF_INET6 && n >= 44 && my_ip6[0] && b[4 + 24] != 0xff) {
            send_eth(gw6_mac, 0x86DD, b + 4, n - 4);
        }
    }
    return NULL;
}

// ---- phone session ----
static int find_phone(void) { // 1 = opened, 0 = nothing, -1 = Samsung present but not tethering
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(ctx, &list);
    int saw_samsung = 0;
    for (ssize_t i = 0; i < cnt && !h; i++) {
        struct libusb_device_descriptor dd;
        struct libusb_config_descriptor *cd;
        if (libusb_get_device_descriptor(list[i], &dd)) continue;
        if (dd.idVendor == 0x04e8) saw_samsung = 1;
        if (libusb_get_active_config_descriptor(list[i], &cd)) continue;
        ctrl_if = data_if = -1; ep_in = ep_out = ep_int = 0; out_mps = 512;
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
        if (ctrl_if < 0 || data_if < 0 || !ep_in || !ep_out) continue;
        printf("phone %04x:%04x, ctrl if %d, data if %d, ep in %02x out %02x int %02x\n",
               dd.idVendor, dd.idProduct, ctrl_if, data_if, ep_in, ep_out, ep_int);
        int r = libusb_open(list[i], &h);
        if (r) { char m[128]; snprintf(m, sizeof m, "libusb_open: %s", libusb_strerror(r)); say(m); h = NULL; }
    }
    libusb_free_device_list(list, 1);
    return h ? 1 : saw_samsung ? -1 : 0;
}

static void usb_close(void) {
    libusb_release_interface(h, data_if);
    libusb_release_interface(h, ctrl_if);
    libusb_close(h);
    h = NULL;
}

static int phone_up(void) {
    int r = find_phone();
    if (r <= 0) {
        say(r < 0 ? "Samsung phone found but USB tethering is off. On the phone: Settings > Connections >\n"
                    "  Mobile Hotspot and Tethering > USB tethering (turn ON)."
                  : "waiting for an RNDIS phone: plug it in and turn on USB tethering");
        return 0;
    }
    if ((r = libusb_claim_interface(h, ctrl_if)) || (r = libusb_claim_interface(h, data_if))) {
        char m[160];
        snprintf(m, sizeof m, "claim interface: %s (is another copy of rndis-bridge running?)", libusb_strerror(r));
        say(m); usb_close();
        return 0;
    }
    link_down = session_end = have_gw_mac = 0;
    my_ip = gw_ip = 0;
    memset(my_ip6, 0, 16);
    if (rndis_init()) { say("RNDIS handshake failed, retrying"); usb_close(); return 0; }
    say("phone connected");
    printf("RNDIS up, host mac %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    rx_start();
    rs_send();
    if (!dhcp() && !link_down) {
        fprintf(stderr, "DHCP failed, using static 192.168.42.100 via 192.168.42.129\n");
        my_ip = inet_addr("192.168.42.100"); gw_ip = dns_ip = inet_addr("192.168.42.129"); lease_secs = 0;
        arp_send(1, zero_mac, gw_ip, bcast);
    }
    char a[16], b[16], c[16];
    printf("IPv4 %s gateway %s dns %s lease %us\n", ip4s(my_ip, a), ip4s(gw_ip, b), ip4s(dns_ip, c), lease_secs);
    return 1;
}

static void phone_down(void) {
    session_end = 1;
    for (int i = 0; i < NRX; i++) libusb_cancel_transfer(rx_xfer[i]);
    pthread_join(ev_thread, NULL);
    for (int i = 0; i < NRX; i++) libusb_free_transfer(rx_xfer[i]);
    if (!link_down) { // RNDIS HALT (no response expected)
        uint8_t m[12] = {0};
        put32(m, 3); put32(m + 4, 12); put32(m + 8, ++reqid);
        libusb_control_transfer(h, 0x21, 0, 0, ctrl_if, m, sizeof m, 1000);
    }
    usb_close();
}

// ---- macOS side ----
static void utun_open(void) {
    tun = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    struct ctl_info ci = {0};
    strlcpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof ci.ctl_name);
    if (tun < 0 || ioctl(tun, CTLIOCGINFO, &ci) < 0) die("utun control socket failed");
    struct sockaddr_ctl sc = {.sc_len = sizeof sc, .sc_family = AF_SYSTEM, .ss_sysaddr = AF_SYS_CONTROL, .sc_id = ci.ctl_id, .sc_unit = 0};
    if (connect(tun, (struct sockaddr *)&sc, sizeof sc) < 0) die("utun connect failed");
    socklen_t l = sizeof ifname;
    if (getsockopt(tun, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &l) < 0) die("utun ifname failed");
    FILE *f = fopen(IFFILE, "w");
    if (f) { fprintf(f, "%s\n", ifname); fclose(f); }
}

static uint32_t cfg_ip, cfg_gw;
static uint8_t cfg6[16];
static int scutil_on;

static void scutil(const char *cmds) {
    FILE *p = popen("/usr/sbin/scutil >/dev/null", "w");
    if (p) { fputs(cmds, p); pclose(p); }
}

// --default: publish the phone as a network service that overrides the primary one. configd then
// points the system default route and DNS at it; removing the keys hands everything back to Wi-Fi.
static void scutil_set(void) {
    // ponytail: IPv4 + DNS only. configd would not make an IPv6 utun service the default, and
    // the resolver skips AAAA lookups without IPv6 on the primary service anyway.
    char cmd[800], a[16], g[16], d[16];
    snprintf(cmd, sizeof cmd,
             "d.init\nd.add Addresses * %s\nd.add DestAddresses * %s\nd.add SubnetMasks * 255.255.255.255\n"
             "d.add InterfaceName %s\nd.add Router %s\nd.add OverridePrimary # 1\nset " SCKEY "/IPv4\n"
             "d.init\nd.add ServerAddresses * %s\nset " SCKEY "/DNS\n",
             ip4s(cfg_ip, a), ip4s(cfg_gw, g), ifname, g, ip4s(dns_ip, d));
    scutil(cmd);
    scutil_on = 1;
    printf("system default route and DNS now go through %s\n", ifname);
}

static void scutil_clear(void) {
    scutil("remove " SCKEY "/IPv4\nremove " SCKEY "/DNS\n");
    if (scutil_on) printf("system default route back to the previous interface\n");
    scutil_on = 0;
}

static void configure4(void) {
    char a[16], g[16];
    if (my_ip == cfg_ip && gw_ip == cfg_gw) return;
    if (cfg_ip) {
        sh("route -q -n delete -ifscope %s default", ifname);
        sh("ifconfig %s inet %s -alias", ifname, ip4s(cfg_ip, a));
    }
    sh("ifconfig %s inet %s %s netmask 255.255.255.255 mtu 1500 up", ifname, ip4s(my_ip, a), ip4s(gw_ip, g));
    // Scoped default: only sockets bound to this interface use it; Wi-Fi stays the system default.
    sh("route -q -n add -ifscope %s default %s", ifname, g);
    cfg_ip = my_ip; cfg_gw = gw_ip;
    if (default_mode) scutil_set();
}

static void configure6(void) {
    uint8_t a[16];
    char s[INET6_ADDRSTRLEN];
    pthread_mutex_lock(&v6_lock);
    memcpy(a, my_ip6, 16);
    pthread_mutex_unlock(&v6_lock);
    if (!a[0] || !memcmp(a, cfg6, 16)) return;
    if (cfg6[0]) {
        sh("route -q -n delete -inet6 -ifscope %s default", ifname);
        sh("ifconfig %s inet6 %s -alias", ifname, ip6s(cfg6, s));
    }
    sh("ifconfig %s inet6 %s prefixlen 128 alias", ifname, ip6s(a, s));
    sh("route -q -n add -inet6 -ifscope %s default -interface %s", ifname, ifname);
    memcpy(cfg6, a, 16);
}

static void teardown(void) {
    printf("\ntearing down %s\n", ifname);
    scutil_clear();
    if (cfg_ip) sh("route -q -n delete -ifscope %s default", ifname);
    if (cfg6[0]) sh("route -q -n delete -inet6 -ifscope %s default", ifname);
    close(tun); // destroys the utun interface and its addresses
    unlink(IFFILE);
}

static int install(int on) {
    if (geteuid()) die("--install/--uninstall need sudo");
    system("launchctl bootout system/" LABEL " 2>/dev/null");
    if (!on) { unlink(PLIST); printf("removed %s\n", PLIST); return 0; }
    char exe[PATH_MAX], real[PATH_MAX];
    uint32_t n = sizeof exe;
    if (_NSGetExecutablePath(exe, &n) || (exe[0] != '/' && !realpath(exe, real))) die("cannot find own path");
    FILE *f = fopen(PLIST, "w");
    if (!f) die("cannot write " PLIST);
    fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
               "<plist version=\"1.0\"><dict>\n"
               "  <key>Label</key><string>" LABEL "</string>\n"
               "  <key>ProgramArguments</key><array><string>%s</string>%s</array>\n"
               "  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n"
               "  <key>StandardOutPath</key><string>/var/log/rndis-bridge.log</string>\n"
               "  <key>StandardErrorPath</key><string>/var/log/rndis-bridge.log</string>\n"
               "</dict></plist>\n", exe[0] == '/' ? exe : real, default_mode ? "<string>--default</string>" : "");
    fclose(f);
    chmod(PLIST, 0644);
    if (sh("launchctl bootstrap system %s", PLIST)) return 1;
    printf("installed: starts at boot and whenever the phone is plugged in. Log: /var/log/rndis-bridge.log\n");
    return 0;
}

static void usage(void) {
    puts("rndis-bridge " VERSION ": Android USB tethering (RNDIS) on macOS\n\n"
         "  rndis-bridge                 dry run: USB handshake + DHCP, no changes\n"
         "  sudo rndis-bridge            bring up a utun; Wi-Fi stays the default route\n"
         "  sudo rndis-bridge --default  also send all system IPv4 traffic and DNS through the phone\n"
         "  sudo rndis-bridge --install [--default]   run as a launchd daemon (auto-start)\n"
         "  sudo rndis-bridge --uninstall\n\n"
         "While running, the interface name is in " IFFILE ".");
}

static void on_sig(int _) { stop = 1; }

int main(int argc, char **argv) {
    int inst = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--default")) default_mode = 1;
        else if (!strcmp(argv[i], "--install")) inst = 1;
        else if (!strcmp(argv[i], "--uninstall")) inst = 0;
        else if (!strcmp(argv[i], "--version")) { puts(VERSION); return 0; }
        else { usage(); return strcmp(argv[i], "-h") && strcmp(argv[i], "--help"); }
    }
    if (inst >= 0) return install(inst);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (libusb_init(&ctx)) die("libusb_init failed");

    if (geteuid() != 0) {
        if (!phone_up()) return 1;
        sleep(1); // give a router advertisement a moment to arrive
        char s[INET6_ADDRSTRLEN];
        printf("IPv6 %s\n", my_ip6[0] ? ip6s(my_ip6, s) : "none (phone sent no router advertisement)");
        phone_down();
        printf("not root: dry run done. Run with sudo to bring up the interface.\n");
        return 0;
    }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    scutil_clear(); // drop keys left by a crashed run
    utun_open();
    printf("interface %s\n", ifname);
    while (!stop) {
        if (!phone_up()) { sleep(2); continue; }
        configure4();
        configure6();
        printf("\n%s is up. Try:  curl --interface %s https://speed.cloudflare.com/cdn-cgi/trace\n", ifname, ifname);
        pthread_t tx;
        pthread_create(&tx, NULL, tx_loop, NULL);
        time_t start = time(NULL), renew_at = lease_secs ? start + lease_secs / 2 : 0;
        while (!stop && !link_down) {
            sleep(1);
            configure6(); // RAs can arrive at any time
            time_t now = time(NULL);
            if (!renew_at || now < renew_at) continue;
            int r = dhcp_renew();
            if (r > 0) { start = now; renew_at = now + lease_secs / 2; printf("DHCP lease renewed (%us)\n", lease_secs); }
            else if (r < 0 || now > start + lease_secs) { printf("DHCP lease lost, reconnecting\n"); link_down = 1; }
            else renew_at = now + 30;
        }
        session_end = 1;
        pthread_join(tx, NULL);
        phone_down();
        if (!stop) {
            printf("phone disconnected, waiting for it to come back\n");
            if (scutil_on) scutil_clear(); // let Wi-Fi carry the system while the phone is gone
            cfg_gw = 0;                    // force configure4 (and scutil) again on reconnect
        }
    }
    teardown();
    libusb_exit(ctx);
    return 0;
}
