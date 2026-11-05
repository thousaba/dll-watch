
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "../src/dll_signature_cache.h"

static const WCHAR *status_name(DLL_SIGNATURE_STATUS status)
{
    switch (status) {
        case DLL_SIGNATURE_VALID: return L"valid";
        case DLL_SIGNATURE_UNSIGNED: return L"unsigned";
        default: return L"failed";
    }
}

static const WCHAR *type_name(DLL_SIGNATURE_TYPE type)
{
    switch (type) {
        case DLL_SIGNATURE_TYPE_EMBEDDED: return L"embedded";
        case DLL_SIGNATURE_TYPE_CATALOG: return L"catalog";
        case DLL_SIGNATURE_TYPE_NONE: return L"none";
        default: return L"unknown";
    }
}

static const WCHAR *cache_name(DLL_SIGNATURE_CACHE_RESULT status)
{
    switch (status) {
        case DLL_SIGNATURE_CACHE_HIT: return L"hit";
        case DLL_SIGNATURE_CACHE_MISS: return L"miss";
        default: return L"bypass";
    }
}

static int append_test_byte(const WCHAR *path)
{
    HANDLE file = CreateFileW(
        path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (file == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateFileW failed: %lu\n", GetLastError());
        return 0;
    }

    BYTE value = 0x42;
    DWORD bytes_written = 0;

    BOOL success = WriteFile(
        file,
        &value,
        sizeof(value),
        &bytes_written,
        NULL
    );

    if (!success) {
        wprintf(L"WriteFile failed: %lu\n", GetLastError());
    }

    if (success && !FlushFileBuffers(file)) {
        wprintf(L"FlushFileBuffers failed: %lu\n", GetLastError());
        success = FALSE;
    }

    CloseHandle(file);

    return success && bytes_written == sizeof(value);
}

static void benchmark_signature_cache(const WCHAR *path)
{
    const int iterations = 1000;

    LARGE_INTEGER frequency, start, end;
    DLL_SIGNATURE_INFO info;
    DLL_SIGNATURE_CACHE_RESULT cache_status;

    int hits = 0;

    if (!QueryPerformanceFrequency(&frequency) ||
        frequency.QuadPart == 0) {
        wprintf(L"High-resolution timer unavailable.\n");
        return;
    }

    // Cache'i temizle: ilk sorgu MISS olmalı.
    dll_signature_cache_clear();

    // 1. Cache MISS ölçümü
    QueryPerformanceCounter(&start);

    if (!dll_signature_cache_inspect(path, &info, &cache_status)) {
        wprintf(L"Initial inspection failed.\n");
        return;
    }

    QueryPerformanceCounter(&end);

    double miss_ms =
        (double)(end.QuadPart - start.QuadPart) * 1000.0 /
        (double)frequency.QuadPart;

    wprintf(L"\n=== SIGNATURE CACHE BENCHMARK ===\n");
    wprintf(L"Initial cache result: %ls\n", cache_name(cache_status));

    // 2. Cache HIT ölçümü
    QueryPerformanceCounter(&start);

    for (int i = 0; i < iterations; i++) {
        if (!dll_signature_cache_inspect(path, &info, &cache_status)) {
            wprintf(L"Benchmark inspection failed.\n");
            return;
        }

        if (cache_status == DLL_SIGNATURE_CACHE_HIT) {
            hits++;
        }
    }

    QueryPerformanceCounter(&end);

    double total_hit_ms =
        (double)(end.QuadPart - start.QuadPart) * 1000.0 /
        (double)frequency.QuadPart;

    double avg_hit_ms = total_hit_ms / iterations;

    wprintf(L"Cache miss:      %.4f ms\n", miss_ms);
    wprintf(L"Cache hit avg:   %.4f ms\n", avg_hit_ms);
    wprintf(L"Cache hits:      %d / %d\n", hits, iterations);

    if (avg_hit_ms > 0.0) {
        wprintf(L"Speedup:         %.2fx\n",
                miss_ms / avg_hit_ms);
    }
}

int wmain(int argc, WCHAR **argv)
{
    if (argc != 2) {
        wprintf(L"Usage: signature_cache_test.exe <cache_fixture.dll>\n");
        return 1;
    }

    // Prevent accidental modification of a real DLL.
    const WCHAR *filename = wcsrchr(argv[1], L'\\');
    filename = filename ? filename + 1 : argv[1];

    if (_wcsicmp(filename, L"cache_fixture.dll") != 0) {
        wprintf(L"Only cache_fixture.dll is allowed for this test.\n");
        return 1;
    }

    for (int i = 0; i < 3; i++) {

        if (i == 2) {
            wprintf(L"\n[TEST] Modifying DLL...\n");

            if (!append_test_byte(argv[1])) {
                wprintf(L"Failed to modify DLL.\n");
                return 1;
            }

            wprintf(L"[TEST] DLL modified successfully.\n");
            wprintf(L"[TEST] Checking cache invalidation...\n\n");
        }

        DLL_SIGNATURE_INFO info;
        DLL_SIGNATURE_CACHE_RESULT cache_status;

        if (!dll_signature_cache_inspect(
                argv[1], &info, &cache_status)) {
            wprintf(L"Inspection failed.\n");
            return 1;
        }

        wprintf(
            L"Run %d | cache=%ls | signature=%ls | type=%ls | signer=%ls\n",
            i + 1,
            cache_name(cache_status),
            status_name(info.status),
            type_name(info.type),
            info.signer[0] ? info.signer : L"none/unavailable"
        );
    }

    DLL_SIGNATURE_CACHE_STATS stats;
    dll_signature_cache_get_stats(&stats);

    wprintf(
        L"\nHits=%llu Misses=%llu Bypasses=%llu "
        L"Invalidations=%llu Evictions=%llu\n",
        (unsigned long long)stats.hits,
        (unsigned long long)stats.misses,
        (unsigned long long)stats.bypasses,
        (unsigned long long)stats.invalidations,
        (unsigned long long)stats.evictions
    );

    benchmark_signature_cache(argv[1]);

    dll_signature_cache_clear();

    return 0;
}
