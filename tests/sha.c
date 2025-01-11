#include "sha.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t num_tests = 0;
size_t num_passed = 0;

static char MILLION_A[10000001];

void
check32_bit_hash(uint32_t *hash, size_t hash_size, char *hexdigest, char *digest, const char *test_name) {
    num_tests++;

    for (size_t i = 0; i < hash_size; i++) {
        sprintf(digest + i * 8, "%08x", hash[i]);
    }

    if (strcmp(digest, hexdigest)) {
        printf("\t[FAILED] %s: expected '%s' got '%s'\n", test_name, hexdigest, digest);
    } else {
        printf("\t[PASSED]: %s\n", test_name);
        num_passed++;
    }
}

void
check64_bit_hash(uint64_t *hash, size_t hash_size, char *hexdigest, char *digest, const char *test_name) {
    num_tests++;

    for (size_t i = 0; i < hash_size; i++) {
        sprintf(digest + i * 16, "%016lx", hash[i]);
    }

    if (strcmp(digest, hexdigest)) {
        printf("\t[FAILED] %s: expected '%s' got '%s'\n", test_name, hexdigest, digest);
    } else {
        printf("\t[PASSED]: %s\n", test_name);
        num_passed++;
    }
}

void
test_sha1(void) {
    uint32_t hash[5];
    char digest[160 / 4 + 1];

    puts("Testing SHA-1...");

    /* Single block */
    sha1("", hash);
    check32_bit_hash(hash, 5, "da39a3ee5e6b4b0d3255bfef95601890afd80709", digest, "empty string");

    sha1("abc", hash);
    check32_bit_hash(hash, 5, "a9993e364706816aba3e25717850c26c9cd0d89d", digest, "short string");

    /* Double block */
    sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 5, "84983e441c3bd26ebaae4aa1f95129e5e54670f1", digest, "long string");

    /* Multi-block */
    sha1(MILLION_A, hash);
    check32_bit_hash(hash, 5, "34aa973cd4c4daa4f61eeb2bdbad27316534016f", digest, "huge string");
}

void
test_sha2_224(void) {
    uint32_t hash[7];
    char digest[224 / 4 + 1];

    puts("Testing SHA-2 224...");

    /* Single block */
    sha2_224("", hash);
    check32_bit_hash(hash, 7, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", digest, "empty string");

    sha2_224("abc", hash);
    check32_bit_hash(hash, 7, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", digest, "short string");

    /* Double block */
    sha2_224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 7, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525", digest, "long string");

    /* Multi-block */
    sha2_224(MILLION_A, hash);
    check32_bit_hash(hash, 7, "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67", digest, "huge string");
}

void
test_sha2_256(void) {
    uint32_t hash[8];
    char digest[256 / 4 + 1];

    puts("Testing SHA-2 256...");

    /* Single block */
    sha2_256("", hash);
    check32_bit_hash(hash, 8, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digest,
                     "empty string");

    sha2_256("abc", hash);
    check32_bit_hash(hash, 8, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digest,
                     "short string");

    /* Double block */
    sha2_256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    check32_bit_hash(hash, 8, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", digest,
                     "long string");

    /* Multi-block */
    sha2_256(MILLION_A, hash);
    check32_bit_hash(hash, 8, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", digest,
                     "huge string");
}

void
test_sha2_384(void) {
    uint64_t hash[6];
    char digest[384 / 4 + 1];

    puts("Testing SHA-2 384...");

    /* Single block */
    sha2_384("", hash);
    check64_bit_hash(hash, 6,
                     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                     digest, "empty string");

    sha2_384("abc", hash);
    check64_bit_hash(hash, 6,
                     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
                     digest, "short string");

    /* Double block */
    sha2_384(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        hash);
    check64_bit_hash(hash, 6,
                     "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
                     digest, "long string");

    /* Multi-block */
    sha2_384(MILLION_A, hash);
    check64_bit_hash(hash, 6,
                     "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
                     digest, "huge string");
}

void
test_sha2_512(void) {
    uint64_t hash[8];
    char digest[512 / 4 + 1];

    puts("Testing SHA-2 512...");

    /* Single block */
    sha2_512("", hash);
    check64_bit_hash(hash, 8,
                     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                     digest, "empty string");

    sha2_512("abc", hash);
    check64_bit_hash(hash, 8,
                     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                     digest, "short string");

    /* Double block */

    sha2_512(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrs"
        "tu",
        hash);
    check64_bit_hash(hash, 8,
                     "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                     "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
                     digest, "long string");

    /* Multi-block */
    sha2_512(MILLION_A, hash);
    check64_bit_hash(hash, 8,
                     "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                     "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
                     digest, "huge string");
}

int
main(void) {
    memset(MILLION_A, 'a', 1000000);
    MILLION_A[1000000] = '\0';

    test_sha1();
    test_sha2_224();
    test_sha2_256();
    test_sha2_384();
    test_sha2_512();

    if (num_tests != num_passed) {
        fprintf(stderr, "%zu/%zu test cases passed\n", num_passed, num_tests);
        return EXIT_FAILURE;
    }

    puts("All test cases passed");
    return EXIT_SUCCESS;
}
