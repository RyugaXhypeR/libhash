#include "sha.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void
check32_bit_hash(uint32_t *hash, size_t hash_size, char *hexdigest, char *digest) {
    for (size_t i = 0; i < hash_size; i++) {
        sprintf(digest + i * 8, "%08x", hash[i]);
    }

    if (strcmp(digest, hexdigest)) {
        printf("Test failed: expected '%s' got '%s'\n", hexdigest, digest);
    } else {
        printf("Test passed: '%s'\n", hexdigest);
    }
}

void
test_sha1(void) {
    uint32_t hash[5];
    char digest[64];

    sha1("", hash);
    check32_bit_hash(hash, 5, "da39a3ee5e6b4b0d3255bfef95601890afd80709", digest);

    sha1("abc", hash);
    check32_bit_hash(hash, 5, "a9993e364706816aba3e25717850c26c9cd0d89d", digest);

    sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 5, "84983e441c3bd26ebaae4aa1f95129e5e54670f1", digest);
}

void
test_sha224(void) {
    uint32_t hash[7];
    char digest[64];

    sha224("", hash);
    check32_bit_hash(hash, 7, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", digest);

    sha224("abc", hash);
    check32_bit_hash(hash, 7, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", digest);

    sha224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 7, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525", digest);
}

int
main(void) {
    test_sha1();
    test_sha224();
}
