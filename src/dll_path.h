#ifndef DLL_PATH_H
#define DLL_PATH_H

#include <windows.h>
#include <stddef.h>

typedef struct DLL_PATH_CLASSIFICATION {
    const WCHAR *location;
    const WCHAR *writable;
} DLL_PATH_CLASSIFICATION;

int dll_path_to_dos(
    const WCHAR *source,
    WCHAR *destination,
    size_t capacity
);

DLL_PATH_CLASSIFICATION classify_dll_path(
    DWORD pid,
    const WCHAR *dll_path
);

void dll_path_print(const WCHAR *path);

void dll_path_print_classification(
    DWORD pid,
    const WCHAR *path
);

#endif