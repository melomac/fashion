#include "CMD5Wrapper.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

unsigned char *CMD5_Oneshot(const void *data, CC_LONG len, unsigned char *digest) {
    return CC_MD5(data, len, digest);
}

int CMD5_Init(CC_MD5_CTX *ctx) {
    return CC_MD5_Init(ctx);
}

int CMD5_Update(CC_MD5_CTX *ctx, const void *data, CC_LONG len) {
    return CC_MD5_Update(ctx, data, len);
}

int CMD5_Final(unsigned char *digest, CC_MD5_CTX *ctx) {
    return CC_MD5_Final(digest, ctx);
}

#pragma clang diagnostic pop
