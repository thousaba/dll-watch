#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "dll_signature_cache.h"

/* These settings favor relatively fresh results over maximum hit rate. */
#define SIGNATURE_CACHE_CAPACITY 256
#define SIGNED_TTL_MS   60000ULL
#define UNSIGNED_TTL_MS 10000ULL

typedef struct {
    WCHAR *path; /* NULL means unused */
    BY_HANDLE_FILE_INFORMATION file_info;
    ULONGLONG verified_at;
    ULONGLONG last_used;
    DLL_SIGNATURE_INFO signature;
} SIGNATURE_CACHE_ENTRY;

static SIGNATURE_CACHE_ENTRY g_entries[SIGNATURE_CACHE_CAPACITY];
static DLL_SIGNATURE_CACHE_STATS g_stats;
static SRWLOCK g_cache_lock = SRWLOCK_INIT;
static ULONGLONG g_access_counter = 0;

/* Metadata lookup is far cheaper than validating a cryptographic signature.
   Opening the target follows any file-system reparse point (normal behavior). */
static int read_file_info(const WCHAR *path, BY_HANDLE_FILE_INFORMATION *info)
{
    HANDLE file = CreateFileW(path, FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;

    BOOL ok = GetFileInformationByHandle(file, info);
    CloseHandle(file);
    return ok != FALSE;
}

static int same_file_version(const BY_HANDLE_FILE_INFORMATION *a,
                             const BY_HANDLE_FILE_INFORMATION *b)
{
    return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber &&
           a->nFileIndexHigh == b->nFileIndexHigh &&
           a->nFileIndexLow == b->nFileIndexLow &&
           a->nFileSizeHigh == b->nFileSizeHigh &&
           a->nFileSizeLow == b->nFileSizeLow &&
           CompareFileTime(&a->ftCreationTime, &b->ftCreationTime) == 0 &&
           CompareFileTime(&a->ftLastWriteTime, &b->ftLastWriteTime) == 0;
}

static ULONGLONG cache_ttl(const DLL_SIGNATURE_INFO *info)
{
    return info->status == DLL_SIGNATURE_UNSIGNED
               ? UNSIGNED_TTL_MS : SIGNED_TTL_MS;
}

static int find_path(const WCHAR *path)
{
    int i;
    for (i = 0; i < SIGNATURE_CACHE_CAPACITY; ++i) {
        if (g_entries[i].path && _wcsicmp(g_entries[i].path, path) == 0)
            return i;
    }
    return -1;
}

/* Must be called while holding g_cache_lock in exclusive mode. */
static void save_result(const WCHAR *path,
                        const BY_HANDLE_FILE_INFORMATION *file_info,
                        const DLL_SIGNATURE_INFO *signature,
                        ULONGLONG now)
{
    int slot = find_path(path);
    int i;

    if (slot < 0) {
        for (i = 0; i < SIGNATURE_CACHE_CAPACITY; ++i) {
            if (!g_entries[i].path) {
                slot = i;
                break;
            }
        }
    }

    if (slot < 0) {
        /* Capacity reached: remove the least-recently-used entry. */
        slot = 0;
        for (i = 1; i < SIGNATURE_CACHE_CAPACITY; ++i) {
            if (g_entries[i].last_used < g_entries[slot].last_used)
                slot = i;
        }
        g_stats.evictions++;
    }

    if (!g_entries[slot].path || _wcsicmp(g_entries[slot].path, path) != 0) {
        size_t count = wcslen(path) + 1;
        if (count > ((size_t)-1) / sizeof(WCHAR))
            return;
        WCHAR *new_path = malloc(count * sizeof(WCHAR));
        if (!new_path)
            return;
        memcpy(new_path, path, count * sizeof(WCHAR));
        free(g_entries[slot].path);
        g_entries[slot].path = new_path;
    }

    g_entries[slot].file_info = *file_info;
    g_entries[slot].signature = *signature;
    g_entries[slot].verified_at = now;
    g_entries[slot].last_used = ++g_access_counter;
}

int dll_signature_cache_inspect(const WCHAR *path,
                                DLL_SIGNATURE_INFO *result,
                                DLL_SIGNATURE_CACHE_RESULT *cache_result)
{
    BY_HANDLE_FILE_INFORMATION before;
    BY_HANDLE_FILE_INFORMATION after;
    ULONGLONG now;
    int slot;
    int checked;

    if (cache_result)
        *cache_result = DLL_SIGNATURE_CACHE_BYPASS;
    if (!result)
        return 0;
    if (!path || !path[0])
        return dll_signature_inspect(path, result);

    /* If metadata is unavailable, do not cache a potentially stale verdict. */
    if (!read_file_info(path, &before)) {
        AcquireSRWLockExclusive(&g_cache_lock);
        g_stats.bypasses++;
        ReleaseSRWLockExclusive(&g_cache_lock);
        return dll_signature_inspect(path, result);
    }

    now = GetTickCount64();
    AcquireSRWLockExclusive(&g_cache_lock);
    slot = find_path(path);
    if (slot >= 0) {
        SIGNATURE_CACHE_ENTRY *entry = &g_entries[slot];
        int same = same_file_version(&entry->file_info, &before);
        if (same && (now - entry->verified_at) < cache_ttl(&entry->signature)) {
            *result = entry->signature;
            entry->last_used = ++g_access_counter;
            g_stats.hits++;
            ReleaseSRWLockExclusive(&g_cache_lock);
            if (cache_result)
                *cache_result = DLL_SIGNATURE_CACHE_HIT;
            return 1;
        }
        if (!same)
            g_stats.invalidations++;
    }
    g_stats.misses++;
    ReleaseSRWLockExclusive(&g_cache_lock);

    /* Never hold the cache lock during expensive WinVerifyTrust calls. */
    checked = dll_signature_inspect(path, result);
    if (!checked || result->status == DLL_SIGNATURE_FAILED ||
        !read_file_info(path, &after) ||
        !same_file_version(&before, &after)) {
        AcquireSRWLockExclusive(&g_cache_lock);
        g_stats.bypasses++;
        ReleaseSRWLockExclusive(&g_cache_lock);
        return checked;
    }

    AcquireSRWLockExclusive(&g_cache_lock);
    save_result(path, &after, result, GetTickCount64());
    ReleaseSRWLockExclusive(&g_cache_lock);
    if (cache_result)
        *cache_result = DLL_SIGNATURE_CACHE_MISS;
    return checked;
}

void dll_signature_cache_get_stats(DLL_SIGNATURE_CACHE_STATS *stats)
{
    if (!stats)
        return;
    AcquireSRWLockExclusive(&g_cache_lock);
    *stats = g_stats;
    ReleaseSRWLockExclusive(&g_cache_lock);
}

void dll_signature_cache_clear(void)
{
    int i;
    AcquireSRWLockExclusive(&g_cache_lock);
    for (i = 0; i < SIGNATURE_CACHE_CAPACITY; ++i) {
        free(g_entries[i].path);
        memset(&g_entries[i], 0, sizeof(g_entries[i]));
    }
    memset(&g_stats, 0, sizeof(g_stats));
    g_access_counter = 0;
    ReleaseSRWLockExclusive(&g_cache_lock);
}
