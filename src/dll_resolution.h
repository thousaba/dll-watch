#ifndef DLL_RESOLUTION_H
#define DLL_RESOLUTION_H

#include <windows.h>

void dll_resolution_record_lookup(
    DWORD pid,
    const WCHAR *path,
    ULONGLONG timestamp
);

void dll_resolution_correlate_load(
    DWORD pid,
    const char *process_path,
    const WCHAR *loaded_path,
    ULONGLONG timestamp
);

#endif
