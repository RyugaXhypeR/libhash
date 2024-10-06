#ifnef _SHA
#define _SHA

#define ROTL(x, n, w) ((x) << (n) | (x) >> (w) - (n))
#define ROTR(x, n, w) ((x) >> (n) | (x) << (w) - (n))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Parity(x, y, z) ((x) ^ (y) ^ (z))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#endif /* _SHA */
