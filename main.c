#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define rotate_right32(data, amount) (((data) >> (amount)) | ((data) << (32 - (amount))))
#define rotate_left32(data, amount) (((data) << (amount)) | ((data) >> (32 - (amount))))
static u_char *padded_message = NULL;
static uint32_t padded_message_len = 0;
int pad_message(const u_char *mymessage, const uint32_t message_len, u_char **out, uint32_t *outlen, uint32_t *outchunks) {
    // TODO Probaly some double bits to bytes conversion here that can be skipped, or rethought
    uint64_t size_b = (uint64_t)message_len * 8;
    // Binary arithmatics to find the nearest value of a multiple of 512 that fits the entire message + 64 bits
    uint32_t nearest = (size_b + 1 + 64 + 511) & ~(512 - 1);
    uint32_t nearest_byte = nearest / 8;
    // printf("pad_len = %d", padded_message_len);
    if (padded_message_len != nearest_byte) {
        free(padded_message);
        padded_message = calloc(1, nearest_byte);
        padded_message_len = nearest_byte;
    }
    if (padded_message == NULL) {
        // printf("It was null\n");
        return -1;
    }
    // line 25
    memcpy(padded_message, mymessage, message_len);
    // Writes the need 1 required by the sha256 standard followed by the last 8 bytes being used for the length of the message.
    padded_message[message_len] = 0b10000000;
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
// The 64 K constant used by sha256
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
// The 8 initial values used by sha256
static const uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

int process_chunk(u_char *const padded_message_chunk, uint32_t chunk_len, uint32_t *h_values) {

    if (chunk_len != 512) {
        printf("chunk_len shall always be 512\n2");
        return 1;
    }
    // Some constant

    // We need 64 words of 32 bit
    uint32_t hashed_array[64];
    // The chunk is 16 words which we copy into the first 16 words of our array,
    // We convert at the same time from Little Endian to Big Endian which is what sha256 is based on
    for (int i = 0; i < 16; i++) {
        hashed_array[i] = ((uint32_t)(unsigned char)padded_message_chunk[i * 4] << 24) |
                          ((uint32_t)(unsigned char)padded_message_chunk[i * 4 + 1] << 16) |
                          ((uint32_t)(unsigned char)padded_message_chunk[i * 4 + 2] << 8) |
                          ((uint32_t)(unsigned char)padded_message_chunk[i * 4 + 3]);
    }
    // Now we need to expand, so we fill out the 64 chunks
    // Using this general formula, starting from position 16
    // W[i] = (w[i-16]+simga0+w[i-7]+sigma1)
    for (int i = 16; i < 64; i++) {
        uint32_t sigma0 = rotate_right32(hashed_array[i - 15], 7) ^ rotate_right32(hashed_array[i - 15], 18) ^ (hashed_array[i - 15] >> 3);
        uint32_t sigma1 = rotate_right32(hashed_array[i - 2], 17) ^ rotate_right32(hashed_array[i - 2], 19) ^ (hashed_array[i - 2] >> 10);
        hashed_array[i] = (hashed_array[i - 16] + sigma0 + hashed_array[i - 7] + sigma1);
    }
    // Now we initialize our 8 working values, based on the passed through variables.
    // Which makes each proccessed chunk dependent on the previous
    uint32_t a = h_values[0], b = h_values[1], c = h_values[2], d = h_values[3];
    uint32_t e = h_values[4], f = h_values[5], g = h_values[6], h = h_values[7];
    for (int i = 0; i < 64; i++) {
        // Now we compute some values based on the previous working values
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t sum0 = rotate_right32(a, 2) ^ rotate_right32(a, 13) ^ rotate_right32(a, 22);
        uint32_t sum1 = rotate_right32(e, 6) ^ rotate_right32(e, 11) ^ rotate_right32(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);

        uint32_t temp1 = h + sum1 + choice + K[i] + hashed_array[i];
        uint32_t temp2 = sum0 + majority;
        // Now we update our working variables for the next itteration of the loop
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    // Now we update our variables passed between each chunk
    h_values[0] += a;
    h_values[1] += b;
    h_values[2] += c;
    h_values[3] += d;
    h_values[4] += e;
    h_values[5] += f;
    h_values[6] += g;
    h_values[7] += h;
    return 0;
}
int sha256_hash(const u_char *mymessage, const uint32_t message_len, u_char **out, uint32_t *outlen) {
    u_char *padded_message = NULL;
    uint32_t padded_length = 0;
    uint32_t chunks = 0;
    pad_message(mymessage, message_len, &padded_message, &padded_length, &chunks);
    uint32_t working_values[8];
    memcpy(working_values, H, 8 * sizeof(uint32_t));
    for (int i = 0; i < chunks; i++) {
        process_chunk(&padded_message[i * 64], 512, working_values);
    }
    // Checks for the case where input is also output, often used for password hashing in loops.
    if (message_len != 32 || mymessage != *out) {
        free(*out);
        *out = malloc(32);
    }

    // After all 8 working values has been processed, these contain our 32 character sha256 hash
    // We convert these back into Little endian
    for (int i = 0; i < 8; i++) {
        (*out)[i * 4] = (working_values[i] >> 24) & 0xFF; // Most significant byte
        (*out)[i * 4 + 1] = (working_values[i] >> 16) & 0xFF;
        (*out)[i * 4 + 2] = (working_values[i] >> 8) & 0xFF;
        (*out)[i * 4 + 3] = working_values[i] & 0xFF; // Least significant byte
    }
    *outlen = 32;
    return 0;
}
int append_salt(const u_char *message, const uint32_t message_len, const u_char *salt, uint32_t salt_len, u_char **out, uint32_t *outlen) {
    *out = malloc(message_len + salt_len);
    if (*out == NULL) {
        return 1;
    }

    memcpy(*out, message, message_len);
    memcpy(*out + message_len, salt, salt_len);
    *outlen = message_len + salt_len;
    return 0;
}
int main() {
    char mymessage[] = "I Love You";
    char mysalt[] = "salt";
    u_char *saltedmesg = NULL;
    uint32_t outlen;
    append_salt((u_char *)mymessage, strlen(mymessage), (u_char *)mysalt, strlen(mymessage), &saltedmesg, &outlen);
    u_char *hashmessage = NULL;
    sha256_hash(saltedmesg, outlen, &hashmessage, &outlen);
    free(saltedmesg);

    uint32_t its = 10;
    for (int i = 0; i < its; i++) {
        sha256_hash((u_char *)hashmessage, sizeof(hashmessage[0]) * outlen, &hashmessage, &outlen);
    }
    free(hashmessage);
    free(padded_message);
    printf("did %d its of sha256 on same message", its);
}
