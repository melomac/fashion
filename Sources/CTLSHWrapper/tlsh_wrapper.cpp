#include "include/tlsh_wrapper.h"
#include "tlsh.h"

extern "C" {

tlsh_t tlsh_new(void) {
    return new Tlsh();
}

void tlsh_free(tlsh_t t) {
    delete static_cast<Tlsh*>(t);
}

void tlsh_update(tlsh_t t, const unsigned char* data, unsigned int len) {
    static_cast<Tlsh*>(t)->update(data, len);
}

void tlsh_final(tlsh_t t) {
    static_cast<Tlsh*>(t)->final();
}

const char* tlsh_get_hash(tlsh_t t, int showvers) {
    return static_cast<Tlsh*>(t)->getHash(showvers);
}

int tlsh_total_diff(tlsh_t t1, tlsh_t t2, int len_diff) {
    return static_cast<Tlsh*>(t1)->totalDiff(static_cast<Tlsh*>(t2), len_diff != 0);
}

int tlsh_from_str(tlsh_t t, const char* str) {
    return static_cast<Tlsh*>(t)->fromTlshStr(str);
}

void tlsh_reset(tlsh_t t) {
    static_cast<Tlsh*>(t)->reset();
}

const char* tlsh_version(void) {
    return Tlsh::version();
}

}
