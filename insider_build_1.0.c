// insider.c
// Simulates a malicious insider modifying a tamper-evident log entry.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define HASH_LEN 32  // SHA256

// This must match the layout used in hash_logger.c
typedef struct {
    unsigned long seq;
    time_t ts;
    uint32_t msg_len;
    unsigned char hash[HASH_LEN]; // H_n = SHA256(prev_hash || msg)
    // Followed by msg_len bytes of message
} __attribute__((packed)) LogHeader;

int main(int argc, char *argv[]) {
    const char *log_path = "tamperlog.bin";
    unsigned long target_seq = 3;  // default: tamper entry with seq=3

    if (argc >= 2) {
        log_path = argv[1];
    }
    if (argc >= 3) {
        target_seq = strtoul(argv[2], NULL, 10);
        if (target_seq == 0) {
            fprintf(stderr,
                    "Invalid target sequence; must be >= 1. Using default (3).\n");
            target_seq = 3;
        }
    }

    printf("[insider] Attempting to tamper with log file: %s\n", log_path);
    printf("[insider] Target sequence number: %lu\n", target_seq);

    FILE *f = fopen(log_path, "r+b");
    if (!f) {
        perror("[insider] Failed to open log file");
        return EXIT_FAILURE;
    }

    unsigned long entries = 0;
    int tampered = 0;

    while (1) {
        LogHeader hdr;
        long header_pos = ftell(f);

        size_t r = fread(&hdr, 1, sizeof(hdr), f);
        if (r == 0) {
            // EOF reached
            break;
        }
        if (r != sizeof(hdr)) {
            fprintf(stderr,
                    "[insider] Partial header read at entry %lu (file truncated?).\n",
                    entries + 1);
            break;
        }

        // Read the message body
        long msg_pos = ftell(f);
        char *msg = (char *)malloc(hdr.msg_len + 1);
        if (!msg) {
            fprintf(stderr, "[insider] malloc failed.\n");
            fclose(f);
            return EXIT_FAILURE;
        }

        r = fread(msg, 1, hdr.msg_len, f);
        if (r != hdr.msg_len) {
            fprintf(stderr,
                    "[insider] Partial message read at seq=%lu "
                    "(expected %u bytes, got %zu).\n",
                    hdr.seq, hdr.msg_len, r);
            free(msg);
            break;
        }
        msg[hdr.msg_len] = '\0';

        entries++;

        if (hdr.seq == target_seq) {
            printf("[insider] Found target entry (seq=%lu).\n", hdr.seq);
            printf("[insider] Original message: \"%s\"\n", msg);

            if (hdr.msg_len > 0) {
                // Simple tampering: flip the first character
                if (msg[0] == 'X')
                    msg[0] = 'Y';
                else
                    msg[0] = 'X';
            }

            // Seek back to the start of the message and overwrite it
            if (fseek(f, msg_pos, SEEK_SET) != 0) {
                fprintf(stderr, "[insider] fseek failed while rewinding.\n");
                free(msg);
                break;
            }

            size_t w = fwrite(msg, 1, hdr.msg_len, f);
            if (w != hdr.msg_len) {
                fprintf(stderr,
                        "[insider] Failed to overwrite message bytes "
                        "(wrote %zu of %u).\n",
                        w, hdr.msg_len);
                free(msg);
                break;
            }

            fflush(f);

            printf("[insider] Modified message: \"%s\"\n", msg);
            printf("[insider] Tampering complete (hash NOT updated).\n");
            tampered = 1;
            free(msg);
            break;  // stop after first tampered entry
        }

        free(msg);

        // Move on to next record; ftell() is already at end of this message.
        (void)header_pos; // silence unused variable warning if any
    }

    if (!tampered) {
        printf("[insider] No entry with seq=%lu was found. No changes made.\n",
               target_seq);
    }

    fclose(f);
    return tampered ? EXIT_SUCCESS : EXIT_FAILURE;
}

