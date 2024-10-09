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
check64_bit_hash(uint64_t *hash, size_t hash_size, char *hexdigest, char *digest) {
    for (size_t i = 0; i < hash_size; i++) {
        sprintf(digest + i * 16, "%016lx", hash[i]);
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
    char digest[160 / 4 + 1];

    /* Single block */
    sha1("", hash);
    check32_bit_hash(hash, 5, "da39a3ee5e6b4b0d3255bfef95601890afd80709", digest);

    sha1("abc", hash);
    check32_bit_hash(hash, 5, "a9993e364706816aba3e25717850c26c9cd0d89d", digest);

    /* Double block */
    sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 5, "84983e441c3bd26ebaae4aa1f95129e5e54670f1", digest);

    /* Multi-block */
    char message[1000000];
    memset(message, 'a', sizeof message);
    sha1(message, hash);
    check32_bit_hash(hash, 5, "34aa973cd4c4daa4f61eeb2bdbad27316534016f", digest);

}

void
test_sha224(void) {
    uint32_t hash[7];
    char digest[224 / 4 + 1];

    /* Single block */
    sha224("", hash);
    check32_bit_hash(hash, 7, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", digest);

    sha224("abc", hash);
    check32_bit_hash(hash, 7, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", digest);

    /* Double block */
    sha224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 7, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525", digest);

    /* Multi-block */
    char message[1000000];
    memset(message, 'a', sizeof message);
    sha224(message, hash);
    check32_bit_hash(hash, 7, "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67", digest);
}

void
test_sha256(void) {
    uint32_t hash[8];
    char digest[256 / 4 + 1];

    /* Single block */
    sha256("", hash);
    check32_bit_hash(hash, 8, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digest);

    sha256("abc", hash);
    check32_bit_hash(hash, 8, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digest);

    /* Double block */
    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 8, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", digest);

    /* Multi-block */
    char message[1000000];
    memset(message, 'a', sizeof message);
    sha256(message, hash);
    check32_bit_hash(hash, 8, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", digest);
}

int
main(void) {
    test_sha1();
    test_sha224();
    test_sha256();
}
