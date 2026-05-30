/*
 * ipc.h — Inter-process communication between server, server_rx, server_tx
 *
 * Architecture:
 *
 *   server        ──(UNIX socket: IPC_RX_PATH)──►  server_rx
 *   server        ◄─(UNIX socket: IPC_TX_PATH)──   server_tx
 *
 * server_rx connects to IPC_RX_PATH and receives MSG_RX frames:
 *   server pushes every decrypted inbound message to server_rx for display.
 *
 * server_tx connects to IPC_TX_PATH and sends MSG_TX_CMD frames:
 *   server_tx sends a (client_id, message) command; server executes the send.
 *   server also pushes CLIENT_LIST frames to server_tx so its UI stays live.
 *
 * Wire format for all frames:
 *   [ ipc_hdr_t (8 bytes) | payload (hdr.len bytes) ]
 *
 * All multi-byte integers are host byte order (local IPC only).
 */

#ifndef IPC_H
#define IPC_H

#include <stdint.h>
#include <stddef.h>

/* ── UNIX socket paths ───────────────────────────────────────────── */
#define IPC_RX_PATH   "/tmp/pqc_rx.sock"   /* server → server_rx       */
#define IPC_TX_PATH   "/tmp/pqc_tx.sock"   /* server_tx → server       */

/* ── Shared capacity constant ────────────────────────────────────── */
#define MAX_CLIENTS   32

/* ── Frame types ─────────────────────────────────────────────────── */
#define IPC_MSG_RX          0x01  /* inbound message from a client      */
#define IPC_MSG_TX_CMD      0x02  /* TX terminal → server: send to cid  */
#define IPC_CLIENT_LIST     0x03  /* server → tx terminal: client list  */
#define IPC_CLIENT_CONNECT  0x04  /* server → rx/tx: new client joined  */
#define IPC_CLIENT_DISCONNECT 0x05 /* server → rx/tx: client left       */
#define IPC_METRICS_RX      0x06  /* server → rx terminal: per-pkt metrics */
#define IPC_METRICS_TX      0x07  /* server → tx terminal: per-send metrics */

/* ── Frame header ────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  type;      /* IPC_* constant above                         */
    uint8_t  _pad;
    uint16_t client_id; /* relevant client (0 = broadcast/global)       */
    uint32_t len;       /* payload length following the header           */
} ipc_hdr_t;

#define IPC_HDR_BYTES  ((int)sizeof(ipc_hdr_t))   /* 8 */

/* ── IPC_MSG_RX payload ──────────────────────────────────────────── */
/*
 * Sent by server → server_rx for every decrypted inbound message.
 * Followed by `msg_len` bytes of plaintext message.
 */
typedef struct __attribute__((packed)) {
    uint16_t client_id;
    char     ip_str[16];    /* nul-terminated IPv4 string               */
    uint16_t port;
    uint64_t session_id;
    uint32_t msg_len;       /* bytes of plaintext that follow           */
    /* [then msg_len bytes of plaintext] */
} ipc_rx_payload_t;

/* ── IPC_MSG_TX_CMD payload ──────────────────────────────────────── */
/*
 * Sent by server_tx → server to request a message be sent to client_id.
 * client_id == 0 means broadcast to all.
 * Followed by `msg_len` bytes of the message.
 */
typedef struct __attribute__((packed)) {
    uint16_t client_id;    /* target client (0 = broadcast)             */
    uint32_t msg_len;      /* bytes of message that follow              */
    /* [then msg_len bytes of message text] */
} ipc_tx_cmd_t;

/* ── IPC_CLIENT_LIST payload ─────────────────────────────────────── */
/*
 * Sent by server → server_tx whenever the client list changes.
 * Payload is: uint16_t count, then count × ipc_client_entry_t structs.
 */
typedef struct __attribute__((packed)) {
    uint16_t client_id;
    char     ip_str[16];
    uint16_t port;
    uint64_t session_id;
    float    hs_total_ms;
    uint32_t msg_count;
    uint32_t bytes_sent_kb;
    uint32_t bytes_recv_kb;
} ipc_client_entry_t;

/* ── IPC_METRICS_RX payload ──────────────────────────────────────── */
/*
 * Per-packet receive metrics sent to server_rx terminal for display.
 * These are measured locally — no metrics travel inside the PQC packet.
 */
typedef struct __attribute__((packed)) {
    uint16_t client_id;
    float    decrypt_us;
    float    interarrival_ms;
    float    jitter_ms;
    float    avg_decrypt_us;
    uint64_t bytes_recv;
    uint32_t pkt_seq;
} ipc_metrics_rx_t;

/* ── IPC_METRICS_TX payload ──────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t client_id;
    float    encrypt_us;
    float    avg_encrypt_us;
    uint64_t bytes_sent;
    uint32_t msg_count;
    uint32_t retransmissions;
} ipc_metrics_tx_t;

/* ── Helper: send a complete IPC frame ──────────────────────────────
 *
 * Writes header + payload atomically in two send() calls.
 * Returns 0 on success, -1 on error.
 */
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

static inline int ipc_send_frame(int fd, uint8_t type, uint16_t client_id,
                                 const void *payload, uint32_t payload_len)
{
    ipc_hdr_t hdr;
    hdr.type      = type;
    hdr._pad      = 0;
    hdr.client_id = client_id;
    hdr.len       = payload_len;

    if (send(fd, &hdr, IPC_HDR_BYTES, MSG_NOSIGNAL) != IPC_HDR_BYTES)
        return -1;
    if (payload_len > 0)
        if (send(fd, payload, payload_len, MSG_NOSIGNAL) != (ssize_t)payload_len)
            return -1;
    return 0;
}

/* ── Helper: receive a complete IPC frame ───────────────────────────
 *
 * Fills *hdr, reads up to buf_max payload bytes into buf.
 * Returns payload bytes read, or -1 on error/disconnect.
 */
static inline ssize_t ipc_recv_frame(int fd, ipc_hdr_t *hdr,
                                     void *buf, size_t buf_max)
{
    ssize_t n = recv(fd, hdr, IPC_HDR_BYTES, MSG_WAITALL);
    if (n != IPC_HDR_BYTES) return -1;

    if (hdr->len == 0) return 0;

    size_t to_read = (hdr->len < buf_max) ? hdr->len : buf_max;
    n = recv(fd, buf, to_read, MSG_WAITALL);
    if (n < 0) return -1;

    /* Drain any excess bytes if payload overflows buf_max */
    if (hdr->len > (uint32_t)buf_max) {
        char drain[256];
        uint32_t remaining = hdr->len - (uint32_t)buf_max;
        while (remaining > 0) {
            size_t chunk = (remaining < sizeof(drain)) ? remaining : sizeof(drain);
            ssize_t r = recv(fd, drain, chunk, MSG_WAITALL);
            if (r <= 0) break;
            remaining -= (uint32_t)r;
        }
    }

    return n;
}

#endif /* IPC_H */
