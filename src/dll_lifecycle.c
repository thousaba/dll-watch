#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "dll_lifecycle.h"
#include "dll_path.h"

#define MAX_LIFECYCLE_RECORDS 4096

typedef struct _DLL_LIFECYCLE_RECORD {
    DWORD pid;
    ULONGLONG image_base;
    ULONGLONG load_timestamp;
    WCHAR *path;
    SYSTEMTIME loaded_at;
} DLL_LIFECYCLE_RECORD;

static DLL_LIFECYCLE_RECORD g_lifecycle_records[MAX_LIFECYCLE_RECORDS];

static void print_time(const SYSTEMTIME *time)
{
    if (time->wYear == 0) {
        printf("<unavailable>");
        return;
    }
    printf("%04u-%02u-%02u %02u:%02u:%02u.%03u",
           time->wYear, time->wMonth, time->wDay,
           time->wHour, time->wMinute, time->wSecond,
           time->wMilliseconds);
}

static SYSTEMTIME event_timestamp_to_local_time(ULONGLONG timestamp)
{
    SYSTEMTIME local_time = {0};
    FILETIME filetime;
    SYSTEMTIME utc_time;
    filetime.dwLowDateTime = (DWORD)(timestamp & 0xFFFFFFFFULL);
    filetime.dwHighDateTime = (DWORD)(timestamp >> 32);
    if (FileTimeToSystemTime(&filetime, &utc_time))
        SystemTimeToTzSpecificLocalTime(NULL, &utc_time, &local_time);
    return local_time;
}

static int is_process_alive(DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return -1;

    PROCESSENTRY32 entry = {0};
    entry.dwSize = sizeof(entry);
    int found = 0;
    if (Process32First(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                found = 1;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    } else if (GetLastError() != ERROR_NO_MORE_FILES) {
        CloseHandle(snapshot);
        return -1;
    }
    CloseHandle(snapshot);
    return found;
}

static WCHAR *copy_wide_string(const WCHAR *value)
{
    size_t length = wcslen(value) + 1;
    WCHAR *copy = malloc(length * sizeof(WCHAR));
    if (copy != NULL)
        memcpy(copy, value, length * sizeof(WCHAR));
    return copy;
}

void dll_lifecycle_handle_event(
    DWORD pid,
    const char *process_path,
    ULONGLONG image_base,
    const WCHAR *path,
    UCHAR opcode,
    ULONGLONG event_timestamp
)
{
    if (opcode == 10) {
        DWORD slot = MAX_LIFECYCLE_RECORDS;
        DWORD oldest_slot = 0;
        ULONGLONG oldest_timestamp = ULLONG_MAX;

        for (DWORD i = 0; i < MAX_LIFECYCLE_RECORDS; i++) {
            DLL_LIFECYCLE_RECORD *record = &g_lifecycle_records[i];
            if (record->path != NULL && record->pid == pid &&
                record->image_base == image_base &&
                _wcsicmp(record->path, path) == 0) {
                slot = i;
                break;
            }
            if (record->path == NULL && slot == MAX_LIFECYCLE_RECORDS)
                slot = i;
            if (record->path != NULL && record->load_timestamp < oldest_timestamp) {
                oldest_timestamp = record->load_timestamp;
                oldest_slot = i;
            }
        }
        if (slot == MAX_LIFECYCLE_RECORDS)
            slot = oldest_slot;

        WCHAR *path_copy = copy_wide_string(path);
        if (path_copy == NULL)
            return;
        free(g_lifecycle_records[slot].path);
        g_lifecycle_records[slot].pid = pid;
        g_lifecycle_records[slot].image_base = image_base;
        g_lifecycle_records[slot].load_timestamp = event_timestamp;
        g_lifecycle_records[slot].path = path_copy;
        g_lifecycle_records[slot].loaded_at =
            event_timestamp_to_local_time(event_timestamp);
        return;
    }

    DWORD match = MAX_LIFECYCLE_RECORDS;
    for (DWORD i = 0; i < MAX_LIFECYCLE_RECORDS; i++) {
        DLL_LIFECYCLE_RECORD *record = &g_lifecycle_records[i];
        if (record->path != NULL && record->pid == pid &&
            record->image_base == image_base &&
            _wcsicmp(record->path, path) == 0) {
            match = i;
            break;
        }
    }

    SYSTEMTIME unloaded_at = event_timestamp_to_local_time(event_timestamp);
    printf("\n[DLL LIFECYCLE]\nPID: %lu\n", (unsigned long)pid);
    printf("Process: %s\n", process_path != NULL
        ? process_path : "<unavailable>");
    printf("Base: 0x%llX\nDLL: ", (unsigned long long)image_base);
    dll_path_print(path);
    printf("\n");
    dll_path_print_classification(pid, path);

    if (match == MAX_LIFECYCLE_RECORDS) {
        printf("Loaded: <before monitoring or unmatched>\nUnloaded: ");
        print_time(&unloaded_at);
        printf("\nLifetime: unavailable\nReason: unmatched unload\n");
        return;
    }

    DLL_LIFECYCLE_RECORD record = g_lifecycle_records[match];
    g_lifecycle_records[match].path = NULL;
    ULONGLONG elapsed_ticks = event_timestamp >= record.load_timestamp
        ? event_timestamp - record.load_timestamp : 0;
    /* ProcessTrace normalizes timestamps to FILETIME unless RAW_TIMESTAMP is set. */
    int lifetime_valid = event_timestamp >= record.load_timestamp;
    double lifetime_ms = lifetime_valid
        ? (double)elapsed_ticks / 10000.0
        : 0;

    printf("Loaded: ");
    print_time(&record.loaded_at);
    printf("\nUnloaded: ");
    print_time(&unloaded_at);
    int process_alive = is_process_alive(pid);
    if (lifetime_valid)
        printf("\nLifetime: %.3f ms\n", lifetime_ms);
    else
        printf("\nLifetime: unavailable\n");
    if (process_alive > 0)
        printf("Process state: alive\nReason: normal unload\n");
    else if (process_alive == 0)
        printf("Process state: teardown\nReason: process teardown\n");
    else
        printf("Process state: unavailable\nReason: unavailable\n");
    free(record.path);
}
