#ifdef __x86_64__
#include <immintrin.h>
#endif
#ifdef __is_target_arch__
#include <arm_neon.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define rotate_right32(data, amount) (((data) >> (amount)) | ((data) << (32 - (amount))))
#define rotate_left32(data, amount) (((data) << (amount)) | ((data) >> (32 - (amount))))
int pad_message(const u_char *mymessage, const uint64_t message_len, const uint64_t nearest_byte, u_char *padded_message) {
    memcpy(padded_message, mymessage, message_len);
    uint64_t size_b = message_len * 8;
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

    return 0;
}
// The 64 K constant used by sha256
static const uint32_t K[64] __attribute__((aligned(16))) = {
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
int process_chunk_x86(u_char *const padded_message_chunk, uint32_t chunk_len, uint32_t *h_values) {

    if (chunk_len != 512) {
        return 1;
    }
    // Some constant

    // We need 64 words of 32 bit aligned to work with simd
    uint32_t hashed_array[64] __attribute__((aligned(16)));
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
    // Hashed_array is words

    // Loads all our initial 16 words alligned

    __m128i W0_3 = _mm_load_si128((const __m128i *)&hashed_array[0]);
    __m128i W4_7 = _mm_load_si128((const __m128i *)&hashed_array[4]);
    __m128i W8_11 = _mm_load_si128((const __m128i *)&hashed_array[8]);
    __m128i W12_15 = _mm_load_si128((const __m128i *)&hashed_array[12]);
    // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html
    for (int i = 16; i < 64; i += 4) {

        // First sigma0 calculations  wi + sigma0
        __m128i abcd = _mm_sha256msg1_epu32(W0_3, W4_7);

        // Now we need to move the aligment by 1 word / 4 bytes
        __m128i efgh = _mm_alignr_epi8(W12_15, W8_11, 4);

        // Now we add them together
        __m128i xdst = _mm_add_epi32(abcd, efgh);

        // Now we do the 2nd message step
        __m128i W16_19 = _mm_sha256msg2_epu32(xdst, W12_15);

        // Stores the values into an aligned buffer
        _mm_store_si128((__m128i *)&hashed_array[i], W16_19);

        W0_3 = W4_7;
        W4_7 = W8_11;
        W8_11 = W12_15;
        W12_15 = W16_19;
    }

    // Precalculate W+K
    uint32_t WK[128] __attribute__((aligned(16)));
    for (int i = 0; i < 64; i++) {
        WK[i] = hashed_array[i] + K[i];
    }
    // Now we initialize our 8 working values, based on the passed through variables.
    // Which makes each proccessed chunk dependent on the previous
    uint32_t a = h_values[0], b = h_values[1], c = h_values[2], d = h_values[3];
    uint32_t e = h_values[4], f = h_values[5], g = h_values[6], h = h_values[7];

    // The x86 instruction requires a certain order or variables in its registers
    __m128i ABEF = _mm_set_epi32(a, b, e, f);
    __m128i CDGH = _mm_set_epi32(c, d, g, h);
    for (int i = 0; i < 64; i += 4) {
        __m128i VK_first = _mm_setr_epi32(WK[i], WK[i + 1], 0, 0);
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, VK_first);
        __m128i VK_second = _mm_setr_epi32(WK[i + 2], WK[i + 3], 0, 0);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, VK_second);
    }

    // Now we take the 2 high values from both and combine them
    __m128i ABCD = _mm_unpackhi_epi64(CDGH, ABEF);
    // Now we take the 2 low values from both and combine them
    __m128i EFGH = _mm_unpacklo_epi64(CDGH, ABEF);

    // We switch the order of values.
    ABCD = _mm_shuffle_epi32(ABCD, _MM_SHUFFLE(0, 1, 2, 3));
    EFGH = _mm_shuffle_epi32(EFGH, _MM_SHUFFLE(0, 1, 2, 3));

    // We load our inital values again
    __m128i initial_ABCD = _mm_loadu_si128((const __m128i *)&h_values[0]);
    __m128i initial_EFGH = _mm_loadu_si128((const __m128i *)&h_values[4]);

    // We add our new values to the inital
    ABCD = _mm_add_epi32(ABCD, initial_ABCD);
    EFGH = _mm_add_epi32(EFGH, initial_EFGH);

    // We store the results
    _mm_storeu_si128((__m128i *)&h_values[0], ABCD);
    _mm_storeu_si128((__m128i *)&h_values[4], EFGH);
    return 0;
}
int sha256_hash(const u_char *mymessage, const uint32_t message_len, u_char out[32]) {
    uint32_t padded_length = 0;
    uint64_t size_b = (uint64_t)message_len * 8;
    uint32_t nearest = (size_b + 1 + 64 + 511) & ~(512 - 1);
    uint32_t nearest_byte = nearest / 8;
    uint32_t chunks = nearest / 512;

    u_char padded_message[nearest_byte];
    memset(padded_message, 0, nearest_byte * sizeof(char));
    pad_message(mymessage, message_len, nearest_byte, padded_message);
    uint32_t working_values[8];
    memcpy(working_values, H, 8 * sizeof(uint32_t));
    for (int i = 0; i < chunks; i++) {
        process_chunk_x86(&padded_message[i * 64], 512, working_values);
        // process_chunk(&padded_message[i * 64], 512, working_values);
    }
    // Checks for the case where input is also output, often used for password hashing in loops.

    // After all 8 working values has been processed, these contain our 32 character sha256 hash
    // We convert these back into Little endian
    for (int i = 0; i < 8; i++) {
        (out)[i * 4] = (working_values[i] >> 24) & 0xFF; // Most significant byte
        (out)[i * 4 + 1] = (working_values[i] >> 16) & 0xFF;
        (out)[i * 4 + 2] = (working_values[i] >> 8) & 0xFF;
        (out)[i * 4 + 3] = working_values[i] & 0xFF; // Least significant byte
    }
    return 0;
}

int append_salt(const u_char *message, const uint32_t message_len, const u_char *salt, uint32_t salt_len, u_char saltedmessage[]) {
    memcpy(saltedmessage, message, message_len);
    memcpy(saltedmessage + message_len, salt, salt_len);
    return 0;
}
int main() {
    char mymessage[] = "I Love You";
    char mysalt[] = "salt";
    uint32_t outlen;
    uint32_t saltlen = strlen(mysalt) + strlen(mymessage);
    u_char saltedmessage[saltlen];
    // append_salt((u_char *)mymessage, strlen(mymessage), (u_char *)mysalt, strlen(mysalt), saltedmessage);
    u_char hashmessage[32] = {0};
    sha256_hash((u_char *)mymessage, strlen(mymessage), hashmessage);
    for (int i = 0; i < 32; i++) {
        printf("%02x", hashmessage[i]);
    }
    uint32_t its = 50000000;
    for (int i = 0; i < its; i++) {
        sha256_hash((u_char *)hashmessage, 32, hashmessage);
    }
}
