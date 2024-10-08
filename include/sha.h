#ifndef _SHA
#define _SHA

#include <stdint.h>

#define CH(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTL(x, n) (((x) << (n)) | ((x) >> ((sizeof(x) * 8) - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << ((sizeof(x) * 8) - (n))))

void sha1(char *message, uint32_t *hash);
void sha224(char *message, uint32_t *hash);
void sha256(char *message, uint32_t *hash);
void sha384(char *message, uint32_t *hash);
void sha512(char *message, uint32_t *hash);

#endif /* _SHA */
