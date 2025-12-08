// read_logs.c
// Prints the contents of tamperlog.bin in human-readable form.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define HASH_LEN 32

typedef struct {
    unsigned long seq;
    time_t ts;
    uint32_t msg_len;
    unsigned char hash[HASH_LEN];
} __attribute__((packed)) LogHeader;

static void hex_print(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

int main(int argc, char *argv[]) {
    const char *log_path = "tamperlog.bin";
    if (argc >= 2)
        log_path = argv[1];

    FILE *f = fopen(log_path, "rb");
    if (!f) {
        perror("Failed to open log file");
        return EXIT_FAILURE;
    }

    printf("=== Tamper-Evident Log Viewer ===\n\n");

    while (1) {
        LogHeader hdr;
        size_t r = fread(&hdr, 1, sizeof(hdr), f);

        if (r == 0) break; // normal EOF
        if (r != sizeof(hdr)) {
            printf("\n[ERROR] Incomplete or corrupt log entry.\n");
            break;
        }

        // Read message
        char *msg = malloc(hdr.msg_len + 1);
        if (!msg) {
            printf("malloc failed\n");
            break;
        }

        r = fread(msg, 1, hdr.msg_len, f);
        if (r != hdr.msg_len) {
            printf("\n[ERROR] Failed to read message body.\n");
            free(msg);
            break;
        }

        msg[hdr.msg_len] = '\0';

        // Print entry
	char timestr[64];
	time_t t = hdr.ts;                         // fix: aligned copy
	struct tm *tm_info = localtime(&t);
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm_info);


        printf("-----------------------------------------------------\n");
        printf("Seq: %lu\n", hdr.seq);
        printf("Timestamp: %s\n", timestr);
        printf("Message: %s\n", msg);
        printf("Hash: ");
        hex_print(hdr.hash, HASH_LEN);
        printf("\n");

        free(msg);
    }

    printf("\n=== End of Log ===\n");
    fclose(f);
    return 0;
}
