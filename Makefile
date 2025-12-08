CC      = gcc
CFLAGS  = -Wall -Wextra -O2 --coverage
LIBS_TLS    = -lssl -lcrypto
LIBS_CRYPTO = -lcrypto

BINARIES = server_tls client_tls verify_log read_logs insider \
           test_hash_logger test_verify_log

.PHONY: all up demo reset clean alpha beta test

# -------------------------------------------------------------------
# Build all main binaries
# -------------------------------------------------------------------
all: up

up: server_tls client_tls verify_log read_logs insider

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

# -------------------------------------------------------------------
# Unit test binaries (beta-level tests)
# -------------------------------------------------------------------

# Simple unit test for hash_logger
test_hash_logger: test_hash_logger.c hash_logger_build_1.0.c hash_logger_build_1.0.h
	$(CC) $(CFLAGS) -o $@ test_hash_logger.c hash_logger_build_1.0.c $(LIBS_CRYPTO)

# Simple unit test for verify_log core
# You can implement verify_log as a non-static function in verify_log_build_1.0.c
# and include its prototype in a small header, or call the binary via system()
test_verify_log: test_verify_log.c hash_logger_build_1.0.c hash_logger_build_1.0.h
	$(CC) $(CFLAGS) -o $@ test_verify_log.c hash_logger_build_1.0.c $(LIBS_CRYPTO)

# -------------------------------------------------------------------
# Log reset helper
# -------------------------------------------------------------------
reset:
	rm -f tamperlog.bin prev_hash.bin

# -------------------------------------------------------------------
# Demo: full vertical slice inside Docker
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# Alpha-level tests (happy-path + 1 negative)
# -------------------------------------------------------------------
alpha: up reset
	@echo "== [A1] Alpha happy-path test =="
	@./server_tls & echo $$! > server.pid
	@sleep 1
	@./client_tls "alpha test message"
	@kill `cat server.pid` 2>/dev/null || true
	@rm -f server.pid
	@sleep 1
	@./verify_log tamperlog.bin
	@echo "[A1] Alpha happy-path PASSED"

	@echo "== [A2] Alpha negative test (tampering) =="
	@./insider tamperlog.bin 3 || true
	@if ./verify_log tamperlog.bin ; then \
	    echo "ERROR: Expected tampering detection, but verify_log succeeded"; \
	    exit 1; \
	 else \
	    echo "[A2] Alpha negative (tamper) PASSED"; \
	 fi

# -------------------------------------------------------------------
# Beta-level tests (unit + extra negative/edge)
# -------------------------------------------------------------------
beta: up reset test_hash_logger test_verify_log
	@echo "== [B1] Unit tests for hash_logger =="
	@./test_hash_logger

	@echo "== [B2] Unit tests for verify_log =="
	@./test_verify_log

	@echo "== [B3] Extra negative test: verify on missing file =="
	@if ./verify_log does_not_exist.bin ; then \
	    echo "ERROR: Expected failure on missing file"; \
	    exit 1; \
	 else \
	    echo "[B3] Negative test (missing file) PASSED"; \
	 fi

test: alpha beta
	@echo "All tests (alpha + beta) PASSED"

# -------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------
clean:
	rm -f $(BINARIES) tamperlog.bin prev_hash.bin server.pid *.gcno *.gcda *.info
