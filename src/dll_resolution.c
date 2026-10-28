#include <windows.h>
#include <limits.h>
#include <stdio.h>
#include <wchar.h>
#include "dll_resolution.h"
#include "dll_path.h"

#define MAX_LOOKUP_ENTRIES 1024
#define LOOKUP_WINDOW_TICKS 50000000ULL

typedef struct _LOOKUP_ENTRY {
    DWORD pid;
    WCHAR dll_name[MAX_PATH];
    WCHAR path[MAX_PATH];
    ULONGLONG timestamp;
    int used;
} LOOKUP_ENTRY;

static LOOKUP_ENTRY g_lookup_entries[MAX_LOOKUP_ENTRIES];

static const WCHAR *dll_basename(const WCHAR *path)
{
    const WCHAR *base = path;
    const WCHAR *separator;

    if (path == NULL)
        return L"";
    separator = wcsrchr(base, L'\\');
    if (separator != NULL)
        base = separator + 1;
    separator = wcsrchr(base, L'/');
    if (separator != NULL)
        base = separator + 1;
    return base;
}

static void expire_lookup_entries(ULONGLONG current_timestamp)
{
    for (DWORD i = 0; i < MAX_LOOKUP_ENTRIES; i++) {
        LOOKUP_ENTRY *entry = &g_lookup_entries[i];
        if (entry->used && current_timestamp >= entry->timestamp &&
            current_timestamp - entry->timestamp > LOOKUP_WINDOW_TICKS)
            entry->used = 0;
    }
}

void dll_resolution_record_lookup(
    DWORD pid,
    const WCHAR *path,
    ULONGLONG timestamp
)
{
    DWORD slot = MAX_LOOKUP_ENTRIES;
    DWORD oldest_slot = 0;
    ULONGLONG oldest_timestamp = ULLONG_MAX;
    const WCHAR *base = dll_basename(path);

    expire_lookup_entries(timestamp);
    for (DWORD i = 0; i < MAX_LOOKUP_ENTRIES; i++) {
        LOOKUP_ENTRY *entry = &g_lookup_entries[i];
        if (!entry->used) {
            slot = i;
            break;
        }
        if (entry->timestamp < oldest_timestamp) {
            oldest_timestamp = entry->timestamp;
            oldest_slot = i;
        }
    }
    if (slot == MAX_LOOKUP_ENTRIES)
        slot = oldest_slot;

    LOOKUP_ENTRY *entry = &g_lookup_entries[slot];
    entry->pid = pid;
    wcsncpy(entry->dll_name, base, MAX_PATH - 1);
    entry->dll_name[MAX_PATH - 1] = L'\0';
    wcsncpy(entry->path, path, MAX_PATH - 1);
    entry->path[MAX_PATH - 1] = L'\0';
    entry->timestamp = timestamp;
    entry->used = 1;
}

void dll_resolution_correlate_load(
    DWORD pid,
    const char *process_path,
    const WCHAR *loaded_path,
    ULONGLONG timestamp
)
{
    const WCHAR *loaded_name = dll_basename(loaded_path);
    int header_printed = 0;

    expire_lookup_entries(timestamp);
    for (DWORD i = 0; i < MAX_LOOKUP_ENTRIES; i++) {
        LOOKUP_ENTRY *entry = &g_lookup_entries[i];
        if (!entry->used || entry->pid != pid ||
            _wcsicmp(entry->dll_name, loaded_name) != 0 ||
            timestamp < entry->timestamp ||
            timestamp - entry->timestamp > LOOKUP_WINDOW_TICKS)
            continue;

        if (!header_printed) {
            printf("\n[DLL RESOLUTION]\nPID: %lu\n",
                   (unsigned long)pid);
            printf("Process: %s\n", process_path != NULL
                ? process_path : "<unavailable>");
            printf("DLL: ");
            dll_path_print(loaded_name);
            printf("\nLookup:\n");
            header_printed = 1;
        }
        printf("  ");
        dll_path_print(entry->path);
        printf("\n  -> NAME NOT FOUND\n");
        entry->used = 0;
    }

    if (header_printed) {
        printf("Loaded:\n  ");
        dll_path_print(loaded_path);
        printf("\n  -> SUCCESS\n");
        fflush(stdout);
    }
}
