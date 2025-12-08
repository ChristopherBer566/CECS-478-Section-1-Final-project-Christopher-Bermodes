// test_hash_logger.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_logger_build_1.0.h"

int main(void) {
    const char *ip = "127.0.0.1";

    // Start from a clean state
    remove("tamperlog.bin");
    remove("prev_hash.bin");

    // 1. Basic log entry
    if (append_log_entry(ip, "unit-test-message-1") != 0) {
        fprintf(stderr, "test_hash_logger: append_log_entry failed on first message\n");
        return 1;
    }

    // 2. Second basic log entry
    if (append_log_entry(ip, "unit-test-message-2") != 0) {
        fprintf(stderr, "test_hash_logger: append_log_entry failed on second message\n");
        return 1;
    }

    // 3. Edge case: empty message
    if (append_log_entry(ip, "") != 0) {
        fprintf(stderr, "test_hash_logger: append_log_entry failed on empty message\n");
        return 1;
    }

    // 4. Sanity check: tamperlog.bin should exist and be non-empty
    FILE *f = fopen("tamperlog.bin", "rb");
    if (!f) {
        fprintf(stderr, "test_hash_logger: tamperlog.bin was not created\n");
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "test_hash_logger: fseek failed\n");
        fclose(f);
        return 1;
    }
    long size = ftell(f);
    fclose(f);

    if (size <= 0) {
        fprintf(stderr, "test_hash_logger: tamperlog.bin is empty or invalid (size=%ld)\n", size);
        return 1;
    }

    printf("test_hash_logger: PASSED (log entries written, file size=%ld bytes)\n", size);
    return 0;
}
