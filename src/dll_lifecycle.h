#ifndef DLL_LIFECYCLE_H
#define DLL_LIFECYCLE_H

#include <windows.h>

void dll_lifecycle_handle_event(
    DWORD pid,
    const char *process_path,
    ULONGLONG image_base,
    const WCHAR *path,
    UCHAR opcode,
    ULONGLONG event_timestamp
);

#endif
