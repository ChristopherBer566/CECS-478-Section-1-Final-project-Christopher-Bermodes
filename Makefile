CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LIBS_TLS    = -lssl -lcrypto
LIBS_CRYPTO = -lcrypto

BINARIES = server_tls client_tls verify_log read_logs insider

.PHONY: all up demo reset clean

all: up

# ----------------------------------------------------------
# Build step: make up
# ----------------------------------------------------------
up: $(BINARIES)

server_tls: server_build_1.0.c hash_logger_build_1.0.c hash_logger_build_1.0.h
	$(CC) $(CFLAGS) -o $@ server_build_1.0.c hash_logger_build_1.0.c $(LIBS_TLS)

client_tls: client_build_1.0.c
	$(CC) $(CFLAGS) -o $@ client_build_1.0.c $(LIBS_TLS)

verify_log: verify_log_build_1.0.c
	$(CC) $(CFLAGS) -o $@ verify_log_build_1.0.c $(LIBS_CRYPTO)

read_logs: read_logs_build_1.0.c
	$(CC) $(CFLAGS) -o $@ read_logs_build_1.0.c $(LIBS_CRYPTO)

insider: insider_build_1.0.c
	$(CC) $(CFLAGS) -o $@ insider_build_1.0.c

# ----------------------------------------------------------
# Reset logs between runs
# ----------------------------------------------------------
reset:
	rm -f tamperlog.bin prev_hash.bin

# ----------------------------------------------------------
# Demo step: make demo
# Runs one vertical slice end-to-end inside Docker
# ----------------------------------------------------------
demo: up reset
	@echo "== Starting server in background =="
	@./server_tls & echo $$! > server.pid
	@sleep 1

	@echo "== Running TLS client (request -> TLS -> log) =="
	@./client_tls "hello from make demo"

	@echo "== Stopping server =="
	@kill `cat server.pid` 2>/dev/null || true
	@rm -f server.pid
	@sleep 1

	@echo "== Verifying log (should be clean) =="
	@./verify_log tamperlog.bin || true

	@echo "== Showing log entries =="
	@./read_logs tamperlog.bin || true

	@echo "== Simulating malicious insider tampering entry 3 =="
	@./insider tamperlog.bin 3 || true

	@echo "== Verifying log again (should detect tampering) =="
	@./verify_log tamperlog.bin || true

	@echo "== Demo complete =="

# ----------------------------------------------------------
# Cleanup
# ----------------------------------------------------------
clean:
	rm -f $(BINARIES) tamperlog.bin prev_hash.bin server.pid
