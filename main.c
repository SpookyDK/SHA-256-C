#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define rotate_right32(data, amount) (((data) >> (amount)) | ((data) << (32 - (amount))))
#define rotate_left32(data, amount) (((data) << (amount)) | ((data) >> (32 - (amount))))

int pad_message(const char *mymessage, const uint32_t message_len, char **out, uint32_t *outlen) {
    uint64_t size_b = message_len * 8;
    printf("Mes lenb = %d\n", size_b);
    uint32_t nearest = (size_b + 1 + 64 + 511) & ~(512 - 1);
    uint32_t nearest_byte = nearest / 8;
    char *padded_message = malloc(nearest_byte);
    if (padded_message == NULL)
        return -1;
    printf("nearest 512 = %d\n", nearest);
    memcpy(padded_message, mymessage, message_len);
    padded_message[message_len] = 0b10000000;
    for (int i = message_len + 1; i < nearest_byte - 8; i++) {
        padded_message[i] = 0;
    }
    padded_message[nearest_byte - 8] = (size_b >> 56) & 0xFF;
    padded_message[nearest_byte - 7] = (size_b >> 48) & 0xFF;
    padded_message[nearest_byte - 6] = (size_b >> 40) & 0xFF;
    padded_message[nearest_byte - 5] = (size_b >> 32) & 0xFF;
    padded_message[nearest_byte - 4] = (size_b >> 24) & 0xFF;
    padded_message[nearest_byte - 3] = (size_b >> 16) & 0xFF;
    padded_message[nearest_byte - 2] = (size_b >> 8) & 0xFF;
    padded_message[nearest_byte - 1] = (size_b) & 0xFF;

    // Set outputs for the caller
    *out = padded_message;
    *outlen = nearest_byte;

    return 0;
}
int do_sha(const char *mymessage, const uint32_t message_len, char *out) {
    char *padded_message = NULL;
    uint32_t padded_length = 0;
    pad_message(mymessage, message_len, &padded_message, &padded_length);
    uint32_t a = 0x6a09e667;
    uint32_t b = 0xbb67ae85;
    uint32_t c = 0x3c6ef372;
    uint32_t d = 0xa54ff53a;
    uint32_t e = 0x510e527f;
    uint32_t f = 0x9b05688c;
    uint32_t g = 0x1f83d9ab;
    uint32_t h = 0x5be0cd19;

    return 0;
}
int main() {

    char mymessage[] = "I Love You";
    do_sha(mymessage, sizeof(mymessage), NULL);
}
