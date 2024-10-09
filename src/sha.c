/* Implementation details are derived from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf */

#include "sha.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* If 128-bit int is supported by the compiler, use that else fallback
 * to 64-bit int for now. */
#ifdef __SIZEOF_INT128__
typedef __uint128_t uint128_t;
#else
typedef uint64_t uint128_t;
#endif

/* SHA-1: 4 constant 32-bit words */
const uint32_t K32_4[] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

/* SHA-224, SHA-265: 64 constant 32-bit words
 * These values represent the first 32bits of fractional parts
 * of cube roots of first 64 prime numbers. */
const uint32_t K32_64[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* SHA-334, SHA-512, SHA-512/224, SHA-512/256:  80 constant 64-bit words
 * These values represent the first 64bits of fractional parts
 * of cube roots of first 80 prime numbers. */
const uint64_t K64_80[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

/* Calculate the padding required by a message with max length 2^64
 *
 * The formula is given by::
 *   l + 1 + k = 448 mod 512
 *
 * where l is length of message in bits (`msg_bit_len` here)
 * and k is the padding required */
uint64_t
pad64_len(uint64_t msg_bit_len) {
    return (448 - (msg_bit_len + 1) % 512 + 512) % 512;
}

/* Calculate the total length required to process `msg_bit_len` with
 * required padding and pad-length consideration */
uint64_t
block64_len(uint64_t msg_bit_len) {
    return msg_bit_len + 1 + pad64_len(msg_bit_len) + 64;
}

/* Prepare the block to be padded in the following format:
 *
 * ``1`` is appended to message followed by ``k`` zeros bits,
 * where ``k``  is the smallest non-negative solution to::
 *
 *  l + 1 + k = 448 mod 512
 *
 * Additional 64-bits are appended to represent the number of bits
 * in the message (without padding). */
void
pad64(uint8_t **block, uint64_t msg_bit_len) {
    uint64_t block_byte_len = block64_len(msg_bit_len) / 8;
    (*block)[msg_bit_len / 8] = 0x80;

    for (int i = 0; i < 8; i++) {
        (*block)[block_byte_len - 8 + i] = (msg_bit_len >> (56 - 8 * i)) & 0xff;
    }
}

/* Resize the message to a size that is divisble by 512, capable
 * of storing 64-bit block in the end for encoding the length of the message */
void
pad64_resize(uint8_t **message, uint64_t msg_bit_len) {
    uint64_t block_len = block64_len(msg_bit_len);

    uint8_t *padded_msg = calloc(block_len, sizeof *padded_msg);
    memcpy(padded_msg, *message, msg_bit_len / 8);
    *message = padded_msg;
}

/* Set of logical functions that are to be performed based on value of ``t`` */
uint32_t
sha1_round(int t, uint32_t x, uint32_t y, uint32_t z) {
    if (t < 20) {
        return CH(x, y, z);
    } else if (t < 40) {
        return PARITY(x, y, z);
    } else if (t < 60) {
        return MAJ(x, y, z);
    } else {
        return PARITY(x, y, z);
    }
}

/* Message schedule for sha1, uses 80 32-bit words. */
uint32_t
sha1_schedule(uint8_t *message, int t) {
    static uint32_t w[80];
    if (t < 16) {
        w[t] = (message[t * 4] << 24) | (message[t * 4 + 1] << 16) | (message[t * 4 + 2] << 8) | (message[t * 4 + 3]);
    } else {
        w[t] = ROTL(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    return w[t];
}

/* Compute the SHA-1 hash for a given message.
 *
 * :param char *message: The input message to be hashed. It can be ASCII string upto 2^64  bits in length.
 * :param uint32_t *hash: A 5-element array storing 160-bit hash as 5 32-bit words.
 *
 * */
void
sha1(char *message, uint32_t *hash) {
    uint8_t *padded_msg = (uint8_t *)message;
    uint64_t message_len = strlen(message);
    uint64_t msg_bit_len = message_len * 8;
    uint64_t num_blocks = block64_len(msg_bit_len) / 512;

    pad64_resize(&padded_msg, msg_bit_len);
    pad64(&padded_msg, msg_bit_len);

    hash[0] = 0x67452301;
    hash[1] = 0xefcdab89;
    hash[2] = 0x98badcfe;
    hash[3] = 0x10325476;
    hash[4] = 0xc3d2e1f0;

    for (uint64_t i = 0; i < num_blocks; i++) {
        uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4];
        uint8_t *block = padded_msg + i * 64;

        for (int t = 0; t < 80; t++) {
            uint32_t temp = ROTL(a, 5) + sha1_round(t, b, c, d) + e + K32_4[t / 20] + sha1_schedule(block, t);
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = temp;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
    }

    free(padded_msg);
}

/* Message schedule for sha25, uses 64 32-bit words */
uint32_t
sha256_schedule(uint8_t *message, int t) {
    static uint32_t w[64];
    if (t < 16) {
        w[t] = (message[t * 4] << 24) | (message[t * 4 + 1] << 16) | (message[t * 4 + 2] << 8) | (message[t * 4 + 3]);
    } else {
        w[t] = SIGMA256_1_SMALL(w[t - 2]) + w[t - 7] + SIGMA256_0_SMALL(w[t - 15]) + w[t - 16];
    }
    return w[t];
}

/* Compute the SHA-224 hash for a given message.
 *
 * :param char *message: The input message to be hashed. It can be ASCII string upto 2^64  bits in length.
 * :param uint32_t *hash: An 8-element array storing 224-bit hash as 7 32-bit words.
 *
 * */
void
sha224(char *message, uint32_t *hash) {
    uint8_t *padded_msg = (uint8_t *)message;
    uint64_t message_len = strlen(message);
    uint64_t msg_bit_len = message_len * 8;
    uint64_t num_blocks = block64_len(msg_bit_len) / 512;

    pad64_resize(&padded_msg, msg_bit_len);
    pad64(&padded_msg, msg_bit_len);

    hash[0] = 0xc1059ed8;
    hash[1] = 0x367cd507;
    hash[2] = 0x3070dd17;
    hash[3] = 0xf70e5939;
    hash[4] = 0xffc00b31;
    hash[5] = 0x68581511;
    hash[6] = 0x64f98fa7;
    hash[7] = 0xbefa4fa4;

    for (uint64_t i = 0; i < num_blocks; i++) {
        uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
        uint8_t *block = padded_msg + i * 64;

        for (int t = 0; t < 64; t++) {
            uint32_t temp1 = h + SIGMA256_1_BIG(e) + CH(e, f, g) + K32_64[t] + sha256_schedule(block, t);
            uint32_t temp2 = SIGMA256_0_BIG(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    free(padded_msg);
}

/* Compute the SHA-256 hash for a given message.
 *
 * :param char *message: The input message to be hashed. It can be ASCII string upto 2^64  bits in length.
 * :param uint32_t *hash: An 8-element array storing 256-bit hash as 8 32-bit words.
 *
 * */
void
sha256(char *message, uint32_t *hash) {
    uint8_t *padded_msg = (uint8_t *)message;
    uint64_t message_len = strlen(message);
    uint64_t msg_bit_len = message_len * 8;
    uint64_t num_blocks = block64_len(msg_bit_len) / 512;

    pad64_resize(&padded_msg, msg_bit_len);
    pad64(&padded_msg, msg_bit_len);

    hash[0] = 0x6a09e667;
    hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372;
    hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f;
    hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab;
    hash[7] = 0x5be0cd19;

    for (uint64_t i = 0; i < num_blocks; i++) {
        uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
        uint8_t *block = padded_msg + i * 64;

        for (int t = 0; t < 64; t++) {
            uint32_t temp1 = h + SIGMA256_1_BIG(e) + CH(e, f, g) + K32_64[t] + sha256_schedule(block, t);
            uint32_t temp2 = SIGMA256_0_BIG(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    free(padded_msg);
}

uint128_t
pad128_len(uint128_t msg_bit_len) {
    return (896 - (msg_bit_len + 1) % 1024 + 1024) % 1024;
}

uint128_t
block128_len(uint128_t msg_bit_len) {
    return msg_bit_len + 1 + pad128_len(msg_bit_len) + 128;
}

void
pad128(uint8_t **block, uint128_t msg_bit_len) {
    uint128_t block_byte_len = block128_len(msg_bit_len) / 8;
    (*block)[msg_bit_len / 8] = 0x80;

    for (int i = 0; i < 16; i++) {
        (*block)[block_byte_len - 16 + i] = (msg_bit_len >> (120 - 8 * i)) & 0xff;
    }
}

void
pad128_resize(uint8_t **message, uint128_t msg_bit_len) {
    uint64_t block_len = block128_len(msg_bit_len);

    uint8_t *padded_msg = calloc(block_len, sizeof *padded_msg);
    memcpy(padded_msg, *message, msg_bit_len / 8);
    *message = padded_msg;
}

uint64_t
sha512_schedule(uint8_t *message, int t) {
    static uint64_t w[80];
    if (t < 16) {
        w[t] = ((uint64_t)message[t * 8] << 56) | ((uint64_t)message[t * 8 + 1] << 48) |
               ((uint64_t)message[t * 8 + 2] << 40) | ((uint64_t)message[t * 8 + 3] << 32) |
               ((uint64_t)message[t * 8 + 4] << 24) | ((uint64_t)message[t * 8 + 5] << 16) |
               ((uint64_t)message[t * 8 + 6] << 8) | ((uint64_t)message[t * 8 + 7]);
    } else {
        w[t] = SIGMA512_1_SMALL(w[t - 2]) + w[t - 7] + SIGMA512_0_SMALL(w[t - 15]) + w[t - 16];
    }
    return w[t];
}

void
sha384(char *message, uint64_t *hash) {
    uint8_t *padded_msg = (uint8_t *)message;
    uint128_t message_len = strlen(message);
    uint128_t msg_bit_len = message_len * 8;
    uint64_t num_blocks = block128_len(msg_bit_len) / 1024;

    pad128_resize(&padded_msg, msg_bit_len);
    pad128(&padded_msg, msg_bit_len);

    hash[0] = 0xcbbb9d5dc1059ed8;
    hash[1] = 0x629a292a367cd507;
    hash[2] = 0x9159015a3070dd17;
    hash[3] = 0x152fecd8f70e5939;
    hash[4] = 0x67332667ffc00b31;
    hash[5] = 0x8eb44a8768581511;
    hash[6] = 0xdb0c2e0d64f98fa7;
    hash[7] = 0x47b5481dbefa4fa4;

    for (uint64_t i = 0; i < num_blocks; i++) {
        uint64_t a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
        uint8_t *block = padded_msg + i * 128;

        for (int t = 0; t < 80; t++) {
            uint64_t temp1 = h + SIGMA512_1_BIG(e) + CH(e, f, g) + K64_80[t] + sha512_schedule(block, t);
            uint64_t temp2 = SIGMA512_0_BIG(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    free(padded_msg);
}
