// hash_logger.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "hash_logger_build_1.0.h"

#define HASH_LEN 32  // SHA256
#define LOG_PATH "tamperlog.bin"
#define STATE_PATH "prev_hash.bin"

static unsigned long g_seq = 1;

typedef struct {
    unsigned long seq;
    time_t ts;
    uint32_t msg_len;
    unsigned char hash[HASH_LEN]; // H_n
    // Followed by `msg_len` bytes of log message
} __attribute__((packed)) LogHeader;


int read_prev_hash(const char *path, unsigned char out[HASH_LEN]) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        // First entry: use all-zero previous hash
        memset(out, 0, HASH_LEN);
        return 0;
    }
    size_t r = fread(out, 1, HASH_LEN, f);
    fclose(f);
    if (r != HASH_LEN) return -1;
    return 0;
}

int write_prev_hash(const char *path, const unsigned char hash[HASH_LEN]) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(hash, 1, HASH_LEN, f);
    fclose(f);
    return (w == HASH_LEN) ? 0 : -1;
}

int append_log(const char *log_path,
               const char *state_path,
               const char *msg,
               unsigned long seq)
{
    unsigned char prev_hash[HASH_LEN];
    unsigned char new_hash[HASH_LEN];
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = EVP_sha256();
    time_t now = time(NULL);
    uint32_t msg_len = (uint32_t)strlen(msg);

    if (read_prev_hash(state_path, prev_hash) != 0) {
        fprintf(stderr, "Failed to read prev_hash\n");
        return -1;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) goto err;
    if (EVP_DigestUpdate(ctx, prev_hash, HASH_LEN) != 1) goto err;
    if (EVP_DigestUpdate(ctx, msg, msg_len) != 1) goto err;

    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx, new_hash, &out_len) != 1) goto err;
    if (out_len != HASH_LEN) goto err;

    EVP_MD_CTX_free(ctx);
    ctx = NULL;

    // Append to log file
    FILE *f = fopen(log_path, "ab");
    if (!f) {
        fprintf(stderr, "Failed to open log file\n");
        return -1;
    }

    LogHeader hdr;
    hdr.seq = seq;
    hdr.ts = now;
    hdr.msg_len = msg_len;
    memcpy(hdr.hash, new_hash, HASH_LEN);

    if (fwrite(&hdr, sizeof(hdr), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    if (fwrite(msg, 1, msg_len, f) != msg_len) {
        fclose(f);
        return -1;
    }
    fclose(f);

    // Update prev_hash
    if (write_prev_hash(state_path, new_hash) != 0) {
        fprintf(stderr, "Failed to write prev_hash\n");
        return -1;
    }
    return 0;

err:
    if (ctx) EVP_MD_CTX_free(ctx);
    fprintf(stderr, "Error computing hash\n");
    return -1;
}

int append_log_entry(const char *client_ip, const char *event_msg) {
        if (!client_ip || !event_msg) {
                return -1;
        }

        size_t ip_len = strlen(client_ip);
        size_t msg_len = strlen(event_msg);
        size_t total_len = ip_len + 3 + msg_len + 1;

        char *combined = (char *)malloc(total_len);
        if (!combined) {
                fprintf(stderr, "append_log_entry: malloc failed\n");
                return -1;
        }

        snprintf(combined, total_len, "%s | %s", client_ip, event_msg);

        int rc = append_log(LOG_PATH, STATE_PATH, combined, g_seq++);

        free(combined);
        return rc;
}
