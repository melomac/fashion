/*
 SwiftPM needs one translation unit per target. This one also verifies the fallback in CMachOCompat.h: on an SDK
 that defines the subtype itself the guarded fallback is inert, and the assertion compares the SDK's value with
 the one the fallback would have supplied.
 */
#include "CMachOCompat.h"

#include <string.h>

_Static_assert(CPU_SUBTYPE_ARM64E_X1 == 12, "CMachOCompat.h fallback for CPU_SUBTYPE_ARM64E_X1 disagrees with the SDK");

/*
 The byte at `index` of the entry's sort key, its name followed by "/" for a directory: -1 past the end, which sorts
 first.
 */
static int key_byte(const FTSENT *entry, size_t index) {
    if (index < entry->fts_namelen) {
        return (unsigned char)entry->fts_name[index];
    }
    if (index == entry->fts_namelen && (entry->fts_info == FTS_D || entry->fts_info == FTS_DC || entry->fts_info == FTS_DNR)) {
        return '/';
    }
    return -1;
}

int fashion_fts_compare(const FTSENT **lhs, const FTSENT **rhs) {
    const FTSENT *a = *lhs;
    const FTSENT *b = *rhs;
    size_t length = a->fts_namelen < b->fts_namelen ? a->fts_namelen : b->fts_namelen;

    int order = memcmp(a->fts_name, b->fts_name, length);
    if (order != 0) {
        return order;
    }
    // Names in one directory differ within a byte past the shorter one; roots are whole paths, and `dir` and `dir/f`
    // only differ further on.
    for (size_t index = length;; index++) {
        int left = key_byte(a, index);
        int right = key_byte(b, index);
        if (left != right || left == -1) {
            return left - right;
        }
    }
}
