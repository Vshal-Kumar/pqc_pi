# Makefile.server — PQC Multi-Client Chat  [SERVER SIDE — x86-64]
#
# Project: Performance Evaluation of SIMD-Accelerated Post-Quantum
#          Cryptography on Embedded ARM Platforms
#
# Binaries built:
#   server      — multi-client PQC server
#   server_rx   — receiver terminal (run in a separate terminal)
#   server_tx   — sender terminal   (run in a separate terminal)
#   bench_pqc   — standalone PQC primitive benchmark
#
# REQUIREMENTS:
#   liboqs  — ML-KEM-768 + ML-DSA-65  (build with Makefile.server_build)
#   openssl — ChaCha20-Poly1305 (libssl + libcrypto)
#
# Build liboqs first (x86_64 WITH AVX2):
#   git clone --depth 1 https://github.com/open-quantum-safe/liboqs
#   cmake -S liboqs -B liboqs/build_x86_64 \
#         -DCMAKE_BUILD_TYPE=Release \
#         -DOQS_BUILD_ONLY_LIB=ON \
#         -DOQS_ENABLE_KEM_ml_kem_768=ON \
#         -DOQS_ENABLE_SIG_ml_dsa_65=ON \
#         -DOQS_USE_AVX2_INSTRUCTIONS=ON \
#         -DBUILD_SHARED_LIBS=OFF
#   cmake --build liboqs/build_x86_64 -j$(nproc)
#
# Usage (three terminals on the server machine):
#   Terminal 1:  make run-server
#   Terminal 2:  make run-rx
#   Terminal 3:  make run-tx
#   Benchmark:   make run-bench

CC      = gcc
ARCH    = x86_64s
LIBOQS  = liboqs/build_x86_64_nosimd

INC     = -I. -I$(LIBOQS)/include
LIBS    = $(LIBOQS)/lib/liboqs.a -lssl -lcrypto -lpthread -lm

# ── Compiler flags ───────────────────────────────────────────────
OPT     = -O3 -march=native -mtune=native -funroll-loops \
          -fomit-frame-pointer -fno-plt
FAST    = $(OPT) -ffast-math
LTO     = -flto=auto
WARN    = -Wall -Wextra -Wno-unused-parameter
DEFS    = -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE

CFLAGS  = $(OPT) $(LTO) $(WARN) $(DEFS) $(INC)
LDFLAGS = $(LTO)

# ── Per-file compilation ─────────────────────────────────────────
transport.o: transport.c transport.h
	$(CC) $(FAST) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

crypto/aead.o: crypto/aead.c crypto/aead.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

wrappers/kem_wrapper.o: wrappers/kem_wrapper.c wrappers/kem_wrapper.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

wrappers/dsa_wrapper.o: wrappers/dsa_wrapper.c wrappers/dsa_wrapper.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

client_registry.o: client_registry.c client_registry.h transport.h
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Object groups ────────────────────────────────────────────────
SHARED_OBJS = transport.o crypto/aead.o \
              wrappers/kem_wrapper.o wrappers/dsa_wrapper.o

SERVER_OBJS = $(SHARED_OBJS) client_registry.o

.PHONY: all server server_rx server_tx bench_pqc clean \
        run-server run-rx run-tx run-bench

all: server server_rx server_tx bench_pqc

# ── Server (multi-client core) ───────────────────────────────────
server: server.c $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)
	@echo "Built: server (x86_64) — multi-client"

# ── Receiver terminal ────────────────────────────────────────────
server_rx: server_rx.c transport.o
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lm $(LDFLAGS)
	@echo "Built: server_rx (receiver terminal)"

# ── Sender terminal ──────────────────────────────────────────────
server_tx: server_tx.c transport.o
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lm $(LDFLAGS)
	@echo "Built: server_tx (sender terminal)"

# ── Benchmark ────────────────────────────────────────────────────
bench_pqc: bench_pqc.c $(SHARED_OBJS)
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -o $@ $^ $(LIBS) $(LDFLAGS) -lm
	@echo "Built: bench_pqc (x86_64)"

# ── Run targets ──────────────────────────────────────────────────
run-server: server
	./server

run-rx: server_rx
	./server_rx

run-tx: server_tx
	./server_tx

run-bench: bench_pqc
	./bench_pqc

# ── Clean ────────────────────────────────────────────────────────
clean:
	rm -f server server_rx server_tx bench_pqc \
	      transport.o client_registry.o \
	      crypto/aead.o \
	      wrappers/kem_wrapper.o wrappers/dsa_wrapper.o