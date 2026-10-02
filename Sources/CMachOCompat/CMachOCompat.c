/*
 SwiftPM needs one translation unit per target. This one also verifies the fallback in CMachOCompat.h: on an SDK
 that defines the subtype itself the guarded fallback is inert, and the assertion compares the SDK's value with
 the one the fallback would have supplied.
 */
#include "CMachOCompat.h"

#include <string.h>

_Static_assert(CPU_SUBTYPE_ARM64E_X1 == 12, "CMachOCompat.h fallback for CPU_SUBTYPE_ARM64E_X1 disagrees with the SDK");

/*
 The byte that follows `length` bytes of the entry's name: the next byte of the name, else "/" for a directory, else
 -1 for the end of a file's name, which sorts first.
 */
static int next_byte(const FTSENT *entry, size_t length) {
    if (entry->fts_namelen > length) {
        return (unsigned char)entry->fts_name[length];
    }
    if (entry->fts_info == FTS_D || entry->fts_info == FTS_DC || entry->fts_info == FTS_DNR) {
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
    return next_byte(a, length) - next_byte(b, length);
}
