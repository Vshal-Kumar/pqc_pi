/*
 * client_registry.c — Thread-safe multi-client registry implementation
 */

#define _POSIX_C_SOURCE 200809L

#include "client_registry.h"
#include "transport.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* ── Internal state ──────────────────────────────────────────────── */
static client_slot_t  g_slots[MAX_CLIENTS];
static pthread_mutex_t g_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── registry_init ───────────────────────────────────────────────── */
void registry_init(void)
{
    pthread_mutex_lock(&g_registry_mutex);
    memset(g_slots, 0, sizeof(g_slots));
    for (int i = 0; i < MAX_CLIENTS; i++) {
        pthread_mutex_init(&g_slots[i].tx_mutex, NULL);
        g_slots[i].active    = 0;
        g_slots[i].client_id = 0;
    }
    pthread_mutex_unlock(&g_registry_mutex);
}

/* ── registry_add ────────────────────────────────────────────────── */
int registry_add(const conn_t *conn, const metrics_t *metrics)
{
    pthread_mutex_lock(&g_registry_mutex);

    /* Find the first free slot */
    int slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_slots[i].active) { slot = i; break; }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_registry_mutex);
        fprintf(stderr, "[registry] MAX_CLIENTS (%d) reached\n", MAX_CLIENTS);
        return -1;
    }

    client_slot_t *s = &g_slots[slot];

    /* Copy connection and metrics */
    memcpy(&s->conn,    conn,    sizeof(conn_t));
    memcpy(&s->metrics, metrics, sizeof(metrics_t));

    /* Assign a stable 1-based ID */
    s->client_id = slot + 1;

    /* Extract IP and port */
    inet_ntop(AF_INET, &conn->peer.sin_addr, s->ip_str, sizeof(s->ip_str));
    s->port       = ntohs(conn->peer.sin_port);
    s->session_id = conn->session_id;

    snprintf(s->tag, sizeof(s->tag), "CLIENT-%02d  %s:%u",
             s->client_id, s->ip_str, s->port);

    s->connect_time_ms = now_ms();
    s->last_send_ns    = 0;
    s->last_recv_ns    = 0;
    s->active          = 1;

    int id = s->client_id;
    pthread_mutex_unlock(&g_registry_mutex);
    return id;
}

/* ── registry_remove ─────────────────────────────────────────────── */
void registry_remove(int client_id)
{
    if (client_id < 1 || client_id > MAX_CLIENTS) return;
    int slot = client_id - 1;

    pthread_mutex_lock(&g_registry_mutex);
    if (g_slots[slot].active && g_slots[slot].client_id == client_id) {
        g_slots[slot].active    = 0;
        g_slots[slot].client_id = 0;
    }
    pthread_mutex_unlock(&g_registry_mutex);
}

/* ── registry_send ───────────────────────────────────────────────── */
int registry_send(int client_id, const uint8_t *msg, uint32_t len)
{
    if (client_id < 1 || client_id > MAX_CLIENTS) return -1;
    int slot = client_id - 1;

    pthread_mutex_lock(&g_registry_mutex);
    if (!g_slots[slot].active || g_slots[slot].client_id != client_id) {
        pthread_mutex_unlock(&g_registry_mutex);
        return -1;
    }
    client_slot_t *s = &g_slots[slot];
    pthread_mutex_unlock(&g_registry_mutex);

    /* Per-client TX mutex: serialize sends to this client */
    pthread_mutex_lock(&s->tx_mutex);
    if (!s->active) {
        pthread_mutex_unlock(&s->tx_mutex);
        return -1;
    }

    s->last_send_ns = now_ns();
    int rc = data_send(&s->conn, &s->metrics, msg, len);

    pthread_mutex_unlock(&s->tx_mutex);
    return rc;
}

/* ── registry_broadcast ──────────────────────────────────────────── */
int registry_broadcast(const uint8_t *msg, uint32_t len)
{
    int success = 0;
    for (int i = 1; i <= MAX_CLIENTS; i++) {
        if (registry_send(i, msg, len) == 0)
            success++;
    }
    return success;
}

/* ── registry_mark_recv ──────────────────────────────────────────── */
void registry_mark_recv(int client_id, uint64_t recv_ns)
{
    if (client_id < 1 || client_id > MAX_CLIENTS) return;
    int slot = client_id - 1;

    pthread_mutex_lock(&g_registry_mutex);
    if (g_slots[slot].active && g_slots[slot].client_id == client_id)
        g_slots[slot].last_recv_ns = recv_ns;
    pthread_mutex_unlock(&g_registry_mutex);
}

/* ── registry_get_snapshot ───────────────────────────────────────── */
int registry_get_snapshot(client_info_t *out, int max)
{
    int count = 0;
    pthread_mutex_lock(&g_registry_mutex);
    for (int i = 0; i < MAX_CLIENTS && count < max; i++) {
        client_slot_t *s = &g_slots[i];
        if (!s->active) continue;

        client_info_t *ci = &out[count++];
        ci->client_id  = s->client_id;
        memcpy(ci->tag,    s->tag,    sizeof(ci->tag));
        memcpy(ci->ip_str, s->ip_str, sizeof(ci->ip_str));
        ci->port       = s->port;
        ci->session_id = s->session_id;
        ci->hs_total_ms = s->metrics.hs_total_ms;
        ci->msg_count   = s->metrics.msg_count;
        ci->bytes_sent  = s->metrics.bytes_sent;
        ci->bytes_recv  = s->metrics.bytes_recv;
        ci->jitter_ms   = s->metrics.jitter_ms;
    }
    pthread_mutex_unlock(&g_registry_mutex);
    return count;
}

/* ── registry_get_conn ───────────────────────────────────────────── */
conn_t *registry_get_conn(int client_id)
{
    if (client_id < 1 || client_id > MAX_CLIENTS) return NULL;
    int slot = client_id - 1;

    pthread_mutex_lock(&g_registry_mutex);
    conn_t *c = (g_slots[slot].active && g_slots[slot].client_id == client_id)
                ? &g_slots[slot].conn : NULL;
    pthread_mutex_unlock(&g_registry_mutex);
    return c;
}

/* ── registry_get_metrics ────────────────────────────────────────── */
metrics_t *registry_get_metrics(int client_id)
{
    if (client_id < 1 || client_id > MAX_CLIENTS) return NULL;
    int slot = client_id - 1;

    pthread_mutex_lock(&g_registry_mutex);
    metrics_t *m = (g_slots[slot].active && g_slots[slot].client_id == client_id)
                   ? &g_slots[slot].metrics : NULL;
    pthread_mutex_unlock(&g_registry_mutex);
    return m;
}

/* ── registry_count ──────────────────────────────────────────────── */
int registry_count(void)
{
    int n = 0;
    pthread_mutex_lock(&g_registry_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_slots[i].active) n++;
    pthread_mutex_unlock(&g_registry_mutex);
    return n;
}
