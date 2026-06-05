#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define rotate_right32(data, amount) (((data) >> (amount)) | ((data) << (32 - (amount))))
#define rotate_left32(data, amount) (((data) << (amount)) | ((data) >> (32 - (amount))))

int pad_message(const char *mymessage, const uint32_t message_len, char **out, uint32_t *outlen, uint32_t *outchunks) {
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
    *outchunks = nearest / 512;

    return 0;
}
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static const uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};
int process_chunk(char *const padded_message_chunk, uint32_t chunk_len) {
    return 1;

    if (chunk_len != 512) {
        printf("chunk_len shall always be 512\n2");
        return 1;
    }
    // Some constant

    // We need 64 words of 32 bit
    uint32_t hashed_array[64];
    // THe chunk is 16 words which we copy into the first 16 words of our array
    memcpy(hashed_array, padded_message_chunk, 512 / 8);
    // Now we need to expand, so we fill out the 64 chunks
    // W16 = (w0+simga0+w9+sigma1)
    for (int i = 16; i < 64; i++) {
        uint32_t sigma0 = rotate_right32(hashed_array[i - 15], 7) ^ rotate_right32(hashed_array[i - 15], 18) ^ (hashed_array[i - 15] >> 3);
        uint32_t sigma1 = rotate_right32(hashed_array[i - 1], 17) ^ rotate_right32(hashed_array[i - 1], 19) ^ (hashed_array[i - 1] >> 10);
        hashed_array[i] = (hashed_array[i - 16] + sigma0 + hashed_array[i - 9] + sigma1);
    }
    // We initialze our working variables
    uint32_t a = 0x6a09e667;
    uint32_t b = 0xbb67ae85;
    uint32_t c = 0x3c6ef372;
    uint32_t d = 0xa54ff53a;
    uint32_t e = 0x510e527f;
    uint32_t f = 0x9b05688c;
    uint32_t g = 0x1f83d9ab;
    uint32_t h = 0x5be0cd19;
    for (int i = 0; i < 64; i++) {
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t sum0 = rotate_right32(a, 2) ^ rotate_right32(a, 13) ^ rotate_right32(a, 22);
        uint32_t sum1 = rotate_right32(e, 6) ^ rotate_right32(e, 11) ^ rotate_right32(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + sum1 + choice + K[i] + hashed_array[i];
        uint32_t temp2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    // we add our final working variables to the constant h values
    uint32_t sha256hash[8];
    sha256hash[0] = H[0] + a;
    sha256hash[1] = H[1] + b;
    sha256hash[2] = H[2] + c;
    sha256hash[3] = H[3] + d;
    sha256hash[4] = H[4] + e;
    sha256hash[5] = H[5] + f;
    sha256hash[6] = H[6] + g;
    sha256hash[7] = H[7] + h;
}

int do_sha(const char *mymessage, const uint32_t message_len, char *out) {
    char *padded_message = NULL;
    uint32_t padded_length = 0;
    uint32_t chunks = 0;
    pad_message(mymessage, message_len, &padded_message, &padded_length, &chunks);

    return 0;
}
int main() {

    char mymessage[] = "I Love You";
    do_sha(mymessage, sizeof(mymessage), NULL);
}
