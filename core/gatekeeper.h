#ifndef GATEKEEPER_H
#define GATEKEEPER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct CdrResult {
    bool ok;
    uint8_t *data;
    size_t len;
    uint8_t *png_data;
    size_t png_len;
    char output_format[16];
    int32_t error_code;
} CdrResult;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Sniff the format of a file without fully decoding it.
 *
 * Returns 0 on success, or a non-zero error code.
 * If successful, the format name (e.g. "Jpeg", "Png") is copied into `out_fmt`.
 * `out_len` specifies the maximum capacity of `out_fmt`.
 */
int32_t gatekeeper_sniff_format(const uint8_t *raw,
                                size_t len,
                                uint8_t *out_fmt,
                                size_t out_len);

/**
 * Disarm and reconstruct a file payload.
 *
 * Returns a `CdrResult`. If `ok` is true, `data` points to the sanitized bytes.
 * The caller MUST pass the result to `gatekeeper_free_result` to avoid memory leaks.
 */
struct CdrResult gatekeeper_disarm(const uint8_t *raw, size_t len);

/**
 * Free a `CdrResult` returned by `gatekeeper_disarm`.
 *
 * It is safe to call this on an error result (where `data` is null).
 */
void gatekeeper_free_result(struct CdrResult result);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // GATEKEEPER_H
