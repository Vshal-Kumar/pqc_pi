/*
 * transport.h — Minimal low-latency UDP transport for local testing
 *
 * CHANGES vs original (multi-client revision):
 *  ► net_metrics_t REMOVED from PKT_DATA wire format.
 *    Metrics are now tracked entirely via local timestamps on both
 *    sender and receiver sides.  Zero wire overhead per packet.
 *  ► data_send() signature unchanged; metrics_t parameter still used
 *    for local accounting but nothing is embedded in the packet.
 *  ► PKT_DATA payload format is now simply:
 *      NONCE(12) | TAG(16) | CIPHERTEXT(n)
 *
 * Packet wire format (unchanged):
 *   +--------+-------+-------+------------------+
 *   | seq(4) |type(1)|len(2) | payload          |
 *   +--------+-------+-------+------------------+
 *         7 bytes header
 *
 * PKT_DATA payload:  NONCE(12) | TAG(16) | CIPHERTEXT(n)
 * Other types:       raw bytes
 */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ── Endpoint ────────────────────────────────────────────────────── */
#define SERVER_PORT   9877
#define SERVER_ADDR   "127.0.0.1"

/* ── Packet types ────────────────────────────────────────────────── */
#define PKT_CLIENT_HELLO  0x01
#define PKT_SERVER_HELLO  0x02
#define PKT_CLIENT_AUTH   0x03
#define PKT_DATA          0x10
#define PKT_ACK           0x11
#define PKT_PING          0x12
#define PKT_PONG          0x13

/* ── Sizing ──────────────────────────────────────────────────────── */
#define PKT_HDR_BYTES     7
#define DATA_CHUNK_MAX    1400
#define PKT_BUF_MAX       65507

/* ── Reliability ─────────────────────────────────────────────────── */
#define ACK_TIMEOUT_US     50000   /* 50 ms — safe for loopback and LAN */
#define RETX_MAX           6
#define RX_POLL_TIMEOUT_US 10000   /* 10 ms */

/* ── Session ID ──────────────────────────────────────────────────── */
#define SESSION_ID_BYTES  8

/* ── On-wire header ──────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t seq;
    uint8_t  type;
    uint16_t len;
} pkt_hdr_t;

/* ── Connection state ────────────────────────────────────────────── */
typedef struct {
    int                sock;
    struct sockaddr_in peer;
    socklen_t          peer_len;

    uint8_t  session_key[32];
    uint32_t tx_seq;
    uint64_t tx_nonce_ctr;
    uint64_t session_id;

    int      established;
} conn_t;

/* ── Metrics ─────────────────────────────────────────────────────── */
/*
 * All metrics are tracked locally on each side.
 * Nothing is embedded in the PKT_DATA wire payload.
 */
typedef struct {
    /* Handshake — PQC breakdown */
    double hs_kem_keygen_ms;
    double hs_dsa_keygen_ms;
    double hs_encap_ms;
    double hs_sign_ms;
    double hs_verify_ms;
    double hs_total_ms;

    /* Per-message transport */
    double   msg_last_rtt_ms;
    double   msg_avg_rtt_ms;
    double   msg_min_rtt_ms;
    double   msg_max_rtt_ms;
    uint64_t msg_count;
    uint64_t retransmissions;
    uint64_t bytes_sent;
    uint64_t bytes_recv;

    /* AEAD cost accumulators (µs) */
    double   total_encrypt_us;
    double   total_decrypt_us;
    uint64_t encrypt_count;
    uint64_t decrypt_count;

    /* Jitter (RFC 3550 EWMA) */
    double   jitter_ms;
    double   prev_rtt_ms;

    /* Timestamps for latency tracking (ns) */
    uint64_t last_send_ns;
    uint64_t prev_recv_ns;
    uint64_t session_start_ns;
} metrics_t;

/* ── Socket creation ─────────────────────────────────────────────── */
int  make_server_sock(void);
int  make_client_sock(void);

/* ── Send / receive ──────────────────────────────────────────────── */
ssize_t pkt_send(conn_t *c, uint8_t type,
                 const uint8_t *payload, uint16_t payload_len);

ssize_t pkt_recv(conn_t *c, pkt_hdr_t *hdr,
                 uint8_t *payload_out, size_t payload_max,
                 int timeout_us);

int pkt_send_reliable(conn_t *c, uint8_t type,
                      const uint8_t *payload, uint16_t payload_len);

void send_ack(conn_t *c, uint32_t ack_seq);

/* ── Data send / receive ─────────────────────────────────────────── */
/*
 * data_send():
 *   Encrypts msg with AEAD, sends NONCE|TAG|CIPHERTEXT.
 *   Measures encrypt cost into m->total_encrypt_us locally.
 *   Nothing extra is embedded in the packet.
 */
int data_send(conn_t *c, metrics_t *m,
              const uint8_t *msg, uint32_t msg_len);

ssize_t data_recv(conn_t *c, uint8_t *out, size_t out_max);

/* ── Metrics ─────────────────────────────────────────────────────── */
void metrics_print(const metrics_t *m);
void metrics_update_rtt(metrics_t *m, uint64_t recv_ns);

/* ── Timing ──────────────────────────────────────────────────────── */
double   now_ms(void);
uint64_t now_ns(void);
void     now_hms(char *buf, int sz);

#endif /* TRANSPORT_H */
