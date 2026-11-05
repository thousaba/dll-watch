#ifndef DLL_ASYNC_H
#define DLL_ASYNC_H

#include <windows.h>


typedef struct {
    DWORD pid;

    ULONGLONG image_base;
    ULONGLONG image_size;
    ULONGLONG timestamp;

    UCHAR opcode;

    WCHAR *dll_path;

    char process_path[MAX_PATH];
    BOOL have_process;

    WCHAR location[32];
    WCHAR writable[16];

} DLLWATCH_IMAGE_JOB;


int dll_async_init(void);

int dll_async_submit(DLLWATCH_IMAGE_JOB *job);

void dll_async_shutdown(void);

#endif