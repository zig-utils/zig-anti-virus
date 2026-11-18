/*
 * zav C ABI. Symbols carry version suffixes; structs begin with their size so fields can be
 * appended. The full API (engine, scratch, buffer/fd/path/stream scans, completion queue) is
 * specified in docs/DESIGN.md section 9.3 and lands with issue P6.12.
 */
#ifndef ZAV_H
#define ZAV_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI generation. Bumped only when an existing symbol changes meaning. */
uint32_t zav_abi_version(void);

/* Library version encoded as major * 10000 + minor * 100 + patch. */
uint32_t zav_version_v1(void);

#ifdef __cplusplus
}
#endif

#endif /* ZAV_H */
