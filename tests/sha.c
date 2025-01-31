#include "sha.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static char MILLION_A[1000001];

struct test_case {
    char *name;
    char *input_str;
    char *expected;
};

size_t num_tests = 0;
size_t num_passed = 0;

#define ARRAY_LEN(array) ((sizeof(array)) / (sizeof *(array)))
#define TEST32(fn, hash_size, cases)                                                                                   \
    do {                                                                                                               \
        puts("Testing " #fn);                                                                                          \
        test_case_32(fn, hash_size, cases, ARRAY_LEN(cases));                                                          \
    } while (0)

#define TEST64(fn, hash_size, cases)                                                                                   \
    do {                                                                                                               \
        puts("Testing " #fn);                                                                                          \
        test_case_64(fn, hash_size, cases, ARRAY_LEN(cases));                                                          \
    } while (0)

void
test_case_32(void (*hash_fn)(const char *, uint32_t *), size_t hash_size, struct test_case *cases, size_t num_cases) {
    uint32_t *hash = malloc(hash_size * (sizeof *hash));

    for (size_t i = 0; i < num_cases; i++) {
        num_tests++;

        struct test_case _case = cases[i];

        hash_fn(_case.input_str, hash);

        char *digest = malloc((strlen(_case.expected) + 1) * (sizeof *digest));
        for (size_t j = 0; j < hash_size; j++) {
            sprintf(digest + j * 8, "%08x", hash[j]);
        }

        if (strcmp(digest, _case.expected)) {
            printf("\t[FAILED] %s: expected '%s' got '%s'\n", _case.name, _case.expected, digest);
        } else {
            printf("\t[PASSED]: %s\n", _case.name);
            num_passed++;
        }

        free(digest);
    }
}

void
test_case_64(void (*hash_fn)(const char *, uint64_t *), size_t hash_size, struct test_case *cases, size_t num_cases) {
    uint64_t *hash = malloc(hash_size * (sizeof *hash));

    for (size_t i = 0; i < num_cases; i++) {
        num_tests++;

        struct test_case _case = cases[i];

        hash_fn(_case.input_str, hash);

        char *digest = malloc((strlen(_case.expected) + 1) * (sizeof *digest));
        for (size_t j = 0; j < hash_size; j++) {
            sprintf(digest + j * 16, "%016lx", hash[j]);
        }

        if (strcmp(digest, _case.expected)) {
            printf("\t[FAILED] %s: expected '%s' got '%s'\n", _case.name, _case.expected, digest);
        } else {
            printf("\t[PASSED]: %s\n", _case.name);
            num_passed++;
        }
    }
}

static struct test_case test_case_sha1[] = {
    {"Empty String", "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"Short String", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
    {"Long String", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
    {"Large String", MILLION_A, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
};

static struct test_case test_case_sha2_224[] = {
    {"Empty String", "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
    {"Short String", "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
    {"Long String", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"},
    {"Large String", MILLION_A, "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"},
};

static struct test_case test_case_sha2_256[] = {
    {"Empty String", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"Short String", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"Long String", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    {"Large String", MILLION_A, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
};

static struct test_case test_case_sha2_384[] = {
    {"Empty String", "",
     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
    {"Short String", "abc",
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
    {"Long String",
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
     "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"},
    {"Large String", MILLION_A,
     "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"},
};

static struct test_case test_case_sha2_512[] = {
    {"Empty String", "",
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
    {"Short String", "abc",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {"Long String",
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
     "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
    {"Large String", MILLION_A,
     "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
     "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"},
};

int
main(void) {
    memset(MILLION_A, 'a', 1000000);
    MILLION_A[1000000] = '\0';

    TEST32(sha1, 5, test_case_sha1);
    TEST32(sha2_224, 7, test_case_sha2_224);
    TEST32(sha2_256, 8, test_case_sha2_256);

    TEST64(sha2_384, 6, test_case_sha2_384);
    TEST64(sha2_512, 8, test_case_sha2_512);

    fprintf(stderr, "%zu/%zu test cases passed\n", num_passed, num_tests);

    return num_passed != num_tests;
}
