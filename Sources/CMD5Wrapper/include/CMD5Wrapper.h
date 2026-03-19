#ifndef CMD5Wrapper_h
#define CMD5Wrapper_h

#include <CommonCrypto/CommonDigest.h>

/** One-shot MD5 hash (wraps `CC_MD5` with deprecation warning suppressed). */
unsigned char *CMD5_Oneshot(const void *data, CC_LONG len, unsigned char *digest);

/** Streaming MD5: initialize context. */
int CMD5_Init(CC_MD5_CTX *ctx);

/** Streaming MD5: feed data. */
int CMD5_Update(CC_MD5_CTX *ctx, const void *data, CC_LONG len);

/** Streaming MD5: finalize and write digest. */
int CMD5_Final(unsigned char *digest, CC_MD5_CTX *ctx);

#endif
