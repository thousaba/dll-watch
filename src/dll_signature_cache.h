#ifndef DLL_SIGNATURE_CACHE_H
#define DLL_SIGNATURE_CACHE_H

#include "dll_signature.h"

/* The cache is process-local and in-memory. It never persists across runs. */
typedef enum {
    DLL_SIGNATURE_CACHE_MISS = 0,
    DLL_SIGNATURE_CACHE_HIT = 1,
    DLL_SIGNATURE_CACHE_BYPASS = 2
} DLL_SIGNATURE_CACHE_RESULT;

typedef struct {
    ULONGLONG hits;
    ULONGLONG misses;
    ULONGLONG bypasses;
    ULONGLONG invalidations;
    ULONGLONG evictions;
} DLL_SIGNATURE_CACHE_STATS;

/* On a hit, returns an existing verified signature result without running
   WinVerifyTrust again. The result pointer must not be NULL.
   The optional cache_result reports hit, miss, or bypass. */
int dll_signature_cache_inspect(const WCHAR *path,
                                DLL_SIGNATURE_INFO *result,
                                DLL_SIGNATURE_CACHE_RESULT *cache_result);

void dll_signature_cache_get_stats(DLL_SIGNATURE_CACHE_STATS *stats);
void dll_signature_cache_clear(void);

#endif
