#ifndef MMT_SAFE_STRING_H
#define MMT_SAFE_STRING_H

#include <string.h>
#include <stdio.h>

/**
 * Safe string copy with explicit size
 * Similar to strlcpy from BSD
 * @param dst Destination buffer
 * @param src Source string
 * @param size Size of destination buffer
 * @return Length of source string
 */
static inline size_t mmt_strlcpy(char *dst, const char *src, size_t size) {
    if (!dst || !src || size == 0) {
        return src ? strlen(src) : 0;
    }

    size_t src_len = strlen(src);
    if (size > 0) {
        size_t copy_len = (src_len >= size) ? size - 1 : src_len;
        memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }
    return src_len;
}

/**
 * Safe string concatenation with explicit size
 * Similar to strlcat from BSD
 * @param dst Destination buffer
 * @param src Source string to append
 * @param size Size of destination buffer
 * @return Total length of string it tried to create
 */
static inline size_t mmt_strlcat(char *dst, const char *src, size_t size) {
    if (!dst || !src || size == 0) {
        return 0;
    }

    size_t dst_len = strnlen(dst, size);
    if (dst_len == size) {
        return dst_len + strlen(src);
    }
    return dst_len + mmt_strlcpy(dst + dst_len, src, size - dst_len);
}

/**
 * Safe snprintf wrapper that guarantees null termination
 */
#define MMT_SAFE_SNPRINTF(buf, size, ...) \
    do { \
        snprintf(buf, size, __VA_ARGS__); \
        buf[(size) - 1] = '\0'; \
    } while(0)

#endif /* MMT_SAFE_STRING_H */
