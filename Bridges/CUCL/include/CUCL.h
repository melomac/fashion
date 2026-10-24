#ifndef CUCL_H
#define CUCL_H

// UCL's safe NRV decompressors, which UPX decompresses its NRV methods with (compress_ucl.cpp), as <ucl/ucl.h> declares
// them: that header includes <ucl/uclconf.h>, which only the target's own sources find.
int ucl_nrv2b_decompress_safe_8(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);
int ucl_nrv2b_decompress_safe_le16(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);
int ucl_nrv2b_decompress_safe_le32(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);
int ucl_nrv2d_decompress_safe_8(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);
int ucl_nrv2d_decompress_safe_le16(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);
int ucl_nrv2d_decompress_safe_le32(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);
int ucl_nrv2e_decompress_safe_8(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);
int ucl_nrv2e_decompress_safe_le16(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);
int ucl_nrv2e_decompress_safe_le32(const unsigned char *src, unsigned int src_len, unsigned char *dst, unsigned int *dst_len, void *wrkmem);

#endif
