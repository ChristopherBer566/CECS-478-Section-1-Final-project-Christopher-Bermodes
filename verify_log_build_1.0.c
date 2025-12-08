// verify_log.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define HASH_LEN 32  // SHA256

// This must match the layout used in hash_logger.c
typedef struct {
    unsigned long seq;
    time_t ts;
    uint32_t msg_len;
    unsigned char hash[HASH_LEN]; // H_n = SHA256(prev_hash || msg)
    // Followed by msg_len bytes of message
} __attribute__((packed)) LogHeader;

static void hex_print(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
}

int verify_log(const char *log_path) {
    FILE *f = fopen(log_path, "rb");
    if (!f) {
        perror("Failed to open log file");
        return -1;
    }

    unsigned char prev_hash[HASH_LEN];
    memset(prev_hash, 0, HASH_LEN);  // initial prev_hash = all zeros

    unsigned long entries = 0;
    int tampered = 0;

    while (1) {
        LogHeader hdr;
        size_t r = fread(&hdr, 1, sizeof(hdr), f);
        if (r == 0) {
            // EOF reached cleanly
            break;
        }
        if (r != sizeof(hdr)) {
            fprintf(stderr,
                    "Partial header read at entry %lu (file truncated or corrupt).\n",
                    entries + 1);
            tampered = 1;
            break;
        }

        // Read the message body
        char *msg = (char *)malloc(hdr.msg_len + 1);
        if (!msg) {
            fprintf(stderr, "malloc failed while reading message.\n");
            fclose(f);
            return -1;
        }

        r = fread(msg, 1, hdr.msg_len, f);
        if (r != hdr.msg_len) {
            fprintf(stderr,
                    "Partial message read at entry %lu (expected %u bytes, got %zu).\n",
                    hdr.seq, hdr.msg_len, r);
            free(msg);
            tampered = 1;
            break;
        }
        msg[hdr.msg_len] = '\0'; // NUL-terminate for printing

        // Recompute hash = SHA256(prev_hash || msg)
        unsigned char computed[HASH_LEN];
        unsigned int out_len = 0;

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            fprintf(stderr, "EVP_MD_CTX_new failed.\n");
            free(msg);
            fclose(f);
            return -1;
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, prev_hash, HASH_LEN) != 1 ||
            EVP_DigestUpdate(ctx, msg, hdr.msg_len) != 1 ||
            EVP_DigestFinal_ex(ctx, computed, &out_len) != 1) {

            fprintf(stderr, "Error computing hash at entry %lu.\n", hdr.seq);
            EVP_MD_CTX_free(ctx);
            free(msg);
            fclose(f);
            return -1;
        }

        EVP_MD_CTX_free(ctx);

        if (out_len != HASH_LEN) {
            fprintf(stderr, "Unexpected hash length at entry %lu.\n", hdr.seq);
            free(msg);
            fclose(f);
            return -1;
        }

        // Compare computed hash with stored hash
        if (memcmp(computed, hdr.hash, HASH_LEN) != 0) {
            printf("\n*** TAMPERING DETECTED ***\n");
            printf("  At log entry seq=%lu\n", hdr.seq);
            printf("  Message: \"%s\"\n", msg);
            printf("  Stored hash : ");
            hex_print(hdr.hash, HASH_LEN);
            printf("\n  Computed hash: ");
            hex_print(computed, HASH_LEN);
            printf("\n");
            tampered = 1;
            free(msg);
            break;
        }

        // Entry is valid
        entries++;
        // For debugging, you can print entries if you like:
        // printf("OK: seq=%lu ts=%ld msg_len=%u msg=\"%s\"\n",
        //        hdr.seq, (long)hdr.ts, hdr.msg_len, msg);

        // Update prev_hash for next entry
        memcpy(prev_hash, computed, HASH_LEN);

        free(msg);
    }

    fclose(f);

    if (!tampered) {
        printf("Verification complete: %lu entries verified.\n", entries);
        printf("Final chain head hash: ");
        hex_print(prev_hash, HASH_LEN);
        printf("\n");
        return 0;
    } else {
        printf("\nLog file appears to have been tampered with.\n");
        return 1;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s tamperlog.bin\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *log_path = argv[1];
    int rc = verify_log(log_path);
    return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
