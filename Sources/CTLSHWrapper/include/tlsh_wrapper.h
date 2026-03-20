#ifndef TLSH_WRAPPER_H
#define TLSH_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void* tlsh_t;

tlsh_t tlsh_new(void);
void tlsh_free(tlsh_t t);
void tlsh_update(tlsh_t t, const unsigned char* data, unsigned int len);
void tlsh_final(tlsh_t t);
const char* tlsh_get_hash(tlsh_t t, int showvers);
int tlsh_total_diff(tlsh_t t1, tlsh_t t2, int len_diff);
int tlsh_from_str(tlsh_t t, const char* str);
void tlsh_reset(tlsh_t t);
const char* tlsh_version(void);

#ifdef __cplusplus
}
#endif

#endif
