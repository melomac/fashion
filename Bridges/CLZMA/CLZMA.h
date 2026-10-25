#ifndef CLZMA_H
#define CLZMA_H

/*
 What LZMABridge calls of liblzma, the xz library macOS ships as /usr/lib/liblzma.5.dylib, which the SDK links
 (liblzma.tbd) but ships no header for. Declared here as xz's lzma.h declares them (base.h, vli.h, filter.h and
 lzma12.h of xz 5.4), whose layouts are frozen ABI: the reserved fields hold their place for it.
 */

#include <stddef.h>
#include <stdint.h>

typedef unsigned char lzma_bool;

/* vli.h */

typedef uint64_t lzma_vli;

static const lzma_vli LZMA_VLI_UNKNOWN = UINT64_MAX;

/* base.h */

typedef enum {
    LZMA_RESERVED_ENUM = 0,
} lzma_reserved_enum;

typedef enum {
    LZMA_OK = 0,
    LZMA_STREAM_END = 1,
    LZMA_NO_CHECK = 2,
    LZMA_UNSUPPORTED_CHECK = 3,
    LZMA_GET_CHECK = 4,
    LZMA_MEM_ERROR = 5,
    LZMA_MEMLIMIT_ERROR = 6,
    LZMA_FORMAT_ERROR = 7,
    LZMA_OPTIONS_ERROR = 8,
    LZMA_DATA_ERROR = 9,
    LZMA_BUF_ERROR = 10,
    LZMA_PROG_ERROR = 11,
    LZMA_SEEK_NEEDED = 12,
} lzma_ret;

typedef enum {
    LZMA_RUN = 0,
    LZMA_SYNC_FLUSH = 1,
    LZMA_FULL_FLUSH = 2,
    LZMA_FINISH = 3,
    LZMA_FULL_BARRIER = 4,
} lzma_action;

typedef struct {
    void *(*alloc)(void *opaque, size_t nmemb, size_t size);
    void (*free)(void *opaque, void *ptr);
    void *opaque;
} lzma_allocator;

typedef struct lzma_internal_s lzma_internal;

typedef struct {
    const uint8_t *next_in;
    size_t avail_in;
    uint64_t total_in;

    uint8_t *next_out;
    size_t avail_out;
    uint64_t total_out;

    const lzma_allocator *allocator;
    lzma_internal *internal;

    void *reserved_ptr1;
    void *reserved_ptr2;
    void *reserved_ptr3;
    void *reserved_ptr4;
    uint64_t reserved_int1;
    uint64_t reserved_int2;
    size_t reserved_int3;
    size_t reserved_int4;
    lzma_reserved_enum reserved_enum1;
    lzma_reserved_enum reserved_enum2;
} lzma_stream;

extern lzma_ret lzma_code(lzma_stream *strm, lzma_action action);
extern void lzma_end(lzma_stream *strm);

/* filter.h */

typedef struct {
    lzma_vli id;
    void *options;
} lzma_filter;

extern lzma_bool lzma_filter_decoder_is_supported(lzma_vli id);
extern lzma_ret lzma_raw_decoder(lzma_stream *strm, const lzma_filter *filters);

/* lzma12.h */

static const lzma_vli LZMA_FILTER_LZMA1 = 0x4000000000000001ULL;
static const lzma_vli LZMA_FILTER_LZMA1EXT = 0x4000000000000002ULL;

static const uint32_t LZMA_DICT_SIZE_MIN = 4096;
static const uint32_t LZMA_DICT_SIZE_MAX = (UINT32_C(1) << 30) + (UINT32_C(1) << 29);

static const uint32_t LZMA_LZMA1EXT_ALLOW_EOPM = 0x01;

typedef enum {
    LZMA_MODE_FAST = 1,
    LZMA_MODE_NORMAL = 2,
} lzma_mode;

typedef enum {
    LZMA_MF_HC3 = 0x03,
    LZMA_MF_HC4 = 0x04,
    LZMA_MF_BT2 = 0x12,
    LZMA_MF_BT3 = 0x13,
    LZMA_MF_BT4 = 0x14,
} lzma_match_finder;

typedef struct {
    uint32_t dict_size;
    const uint8_t *preset_dict;
    uint32_t preset_dict_size;
    uint32_t lc;
    uint32_t lp;
    uint32_t pb;
    lzma_mode mode;
    uint32_t nice_len;
    lzma_match_finder mf;
    uint32_t depth;
    uint32_t ext_flags;
    uint32_t ext_size_low;
    uint32_t ext_size_high;
    uint32_t reserved_int4;
    uint32_t reserved_int5;
    uint32_t reserved_int6;
    uint32_t reserved_int7;
    uint32_t reserved_int8;
    lzma_reserved_enum reserved_enum1;
    lzma_reserved_enum reserved_enum2;
    lzma_reserved_enum reserved_enum3;
    lzma_reserved_enum reserved_enum4;
    void *reserved_ptr1;
    void *reserved_ptr2;
} lzma_options_lzma;

#endif
