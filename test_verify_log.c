// test_verify_log.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_logger_build_1.0.h"

static int run_verify(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "./verify_log %s", path);
    int rc = system(cmd);
    if (rc == -1) {
        fprintf(stderr, "test_verify_log: system() failed when running verify_log\n");
        return -1;
    }
    // We only care about "success" vs "failure" of the verifier
    // Non-zero exit status means verification failed / tampering detected.
    if (rc == 0) {
        return 0;   // verify_log reported success
    } else {
        return 1;   // verify_log reported failure
    }
}

int main(void) {
    const char *ip = "127.0.0.1";

    // Clean existing logs
    remove("tamperlog.bin");
    remove("prev_hash.bin");

    // Build a small log with two entries
    if (append_log_entry(ip, "verify-test-message-1") != 0) {
        fprintf(stderr, "test_verify_log: append_log_entry failed (1)\n");
        return 1;
    }
    if (append_log_entry(ip, "verify-test-message-2") != 0) {
        fprintf(stderr, "test_verify_log: append_log_entry failed (2)\n");
        return 1;
    }

    // Positive case: verify_log should succeed on a clean log
    int ok = run_verify("tamperlog.bin");
    if (ok != 0) {
        fprintf(stderr, "test_verify_log: verify_log failed on a clean log (expected success)\n");
        return 1;
    }

    // Negative case: tamper with the log by flipping the last byte
    FILE *f = fopen("tamperlog.bin", "r+b");
    if (!f) {
        fprintf(stderr, "test_verify_log: could not reopen tamperlog.bin for tampering\n");
        return 1;
    }

    if (fseek(f, -1, SEEK_END) != 0) {
        fprintf(stderr, "test_verify_log: fseek to end failed\n");
        fclose(f);
        return 1;
    }

    int ch = fgetc(f);
    if (ch == EOF) {
        fprintf(stderr, "test_verify_log: failed to read last byte\n");
        fclose(f);
        return 1;
    }

    // Move back one byte and overwrite with a flipped value
    if (fseek(f, -1, SEEK_CUR) != 0) {
        fprintf(stderr, "test_verify_log: fseek back failed\n");
        fclose(f);
        return 1;
    }

    unsigned char new_ch = (unsigned char)ch ^ 0xFF; // simple flip
    if (fputc(new_ch, f) == EOF) {
        fprintf(stderr, "test_verify_log: failed to write tampered byte\n");
        fclose(f);
        return 1;
    }

    fclose(f);

    // Now verify_log should *fail* on the tampered log
    ok = run_verify("tamperlog.bin");
    if (ok == 0) {
        fprintf(stderr, "test_verify_log: verify_log incorrectly succeeded on tampered log\n");
        return 1;
    }

    printf("test_verify_log: PASSED (clean log accepted, tampered log rejected)\n");
    return 0;
}
