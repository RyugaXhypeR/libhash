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
    char digest[160];

    sha1("", hash);
    check32_bit_hash(hash, 5, "da39a3ee5e6b4b0d3255bfef95601890afd80709", digest);

    sha1("abc", hash);
    check32_bit_hash(hash, 5, "a9993e364706816aba3e25717850c26c9cd0d89d", digest);

    sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 5, "84983e441c3bd26ebaae4aa1f95129e5e54670f1", digest);
}

int
main(void) {
    test_sha1();
}
