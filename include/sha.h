#ifndef _SHA
#define _SHA

#define CH(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTL(x, n) (((x) << (n)) | ((x) >> ((sizeof(x) * 8) - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << ((sizeof(x) * 8) - (n))))

#endif /* _SHA */
