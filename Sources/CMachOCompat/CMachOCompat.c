/*
 SwiftPM needs one translation unit per target. This one also verifies the fallbacks in CMachOCompat.h: on an SDK
 that defines a constant itself the guarded fallback is inert, and the assertion compares the SDK's value with
 the one the fallback would have supplied.
 */
#include "CMachOCompat.h"

#include <string.h>

_Static_assert(CPU_SUBTYPE_ARM64E_X1 == 12, "CMachOCompat.h fallback for CPU_SUBTYPE_ARM64E_X1 disagrees with the SDK");
_Static_assert(LC_FUNCTION_VARIANTS == 0x37, "CMachOCompat.h fallback for LC_FUNCTION_VARIANTS disagrees with the SDK");
_Static_assert(LC_FUNCTION_VARIANT_FIXUPS == 0x38, "CMachOCompat.h fallback for LC_FUNCTION_VARIANT_FIXUPS disagrees with the SDK");
_Static_assert(LC_TARGET_TRIPLE == 0x39, "CMachOCompat.h fallback for LC_TARGET_TRIPLE disagrees with the SDK");
_Static_assert(LC_LAZY_LOAD_DYLIB_INFO == 0x3A, "CMachOCompat.h fallback for LC_LAZY_LOAD_DYLIB_INFO disagrees with the SDK");

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

static int is_digit(int byte) {
    return byte >= '0' && byte <= '9';
}

/*
 The end of the number that starts at `index` in the entry's name. The "/" that follows a directory's name is no digit,
 so a number ends within the name.
 */
static size_t number_end(const FTSENT *entry, size_t index) {
    while (index < entry->fts_namelen && is_digit((unsigned char)entry->fts_name[index])) {
        index++;
    }
    return index;
}

/*
 Order the numbers at `*left` in `a` and `*right` in `b`, and move both past theirs: by value, then the one written with
 more leading zeros first, as bytes would order them ("007" < "07" < "7"). Numbers of any length compare without
 overflow: past their leading zeros, the longer is the larger, and two of one length compare digit by digit.
 */
static int compare_numbers(const FTSENT *a, size_t *left, const FTSENT *b, size_t *right) {
    size_t a_start = *left;
    size_t b_start = *right;
    size_t a_end = number_end(a, a_start);
    size_t b_end = number_end(b, b_start);
    *left = a_end;
    *right = b_end;

    size_t a_digits = a_start;
    size_t b_digits = b_start;
    while (a_digits < a_end && a->fts_name[a_digits] == '0') {
        a_digits++;
    }
    while (b_digits < b_end && b->fts_name[b_digits] == '0') {
        b_digits++;
    }
    if (a_end - a_digits != b_end - b_digits) {
        return a_end - a_digits < b_end - b_digits ? -1 : 1;
    }
    int order = memcmp(a->fts_name + a_digits, b->fts_name + b_digits, a_end - a_digits);
    if (order != 0) {
        return order;
    }
    if (a_end - a_start != b_end - b_start) {
        return a_end - a_start > b_end - b_start ? -1 : 1;
    }
    return 0;
}

int fashion_fts_compare(const FTSENT **lhs, const FTSENT **rhs) {
    const FTSENT *a = *lhs;
    const FTSENT *b = *rhs;
    size_t left = 0;
    size_t right = 0;

    // Names in one directory differ within a byte past the shorter one; roots are whole paths, and `dir` and `dir/f`
    // only differ further on. Past numbers of unequal length, the two keys go on at different indexes.
    for (;;) {
        int left_byte = key_byte(a, left);
        int right_byte = key_byte(b, right);
        if (is_digit(left_byte) && is_digit(right_byte)) {
            int order = compare_numbers(a, &left, b, &right);
            if (order != 0) {
                return order;
            }
        } else if (left_byte != right_byte || left_byte == -1) {
            return left_byte - right_byte;
        } else {
            left++;
            right++;
        }
    }
}
