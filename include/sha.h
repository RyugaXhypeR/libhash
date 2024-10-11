#ifndef _SHA
#define _SHA

#include <stdint.h>

#define CH(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTL(x, n) (((x) << (n)) | ((x) >> ((sizeof(x) * 8) - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << ((sizeof(x) * 8) - (n))))

#define SIGMA256_0_BIG(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA256_1_BIG(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#define SIGMA256_0_SMALL(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIGMA256_1_SMALL(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

#define SIGMA512_0_BIG(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SIGMA512_1_BIG(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))

#define SIGMA512_0_SMALL(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ ((x) >> 7))
#define SIGMA512_1_SMALL(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ ((x) >> 6))


/* SHA-1 Family */
void sha1(char *message, uint32_t *hash);

/* SHA-2 Family */
void sha2_224(char *message, uint32_t *hash);
void sha2_256(char *message, uint32_t *hash);
void sha2_384(char *message, uint64_t *hash);
void sha2_512(char *message, uint64_t *hash);

/* SHA-3 Family */
void sha3_224(char *message, uint64_t *hash);
void sha3_256(char *message, uint64_t *hash);
void sha3_384(char *message, uint64_t *hash);
void sha3_512(char *message, uint64_t *hash);


#endif /* _SHA */
