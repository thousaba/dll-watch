#ifndef ETW_MONITOR_H
#define ETW_MONITOR_H

#include <windows.h>

typedef enum DLLWATCH_FILTER {
    DLLWATCH_FILTER_ALL = 0,
    DLLWATCH_FILTER_UNLOAD,
    DLLWATCH_FILTER_NOT_FOUND,
    DLLWATCH_FILTER_LIFECYCLE
} DLLWATCH_FILTER;

int monitor_pid(DWORD pid);
int monitor_name(const char *process_name);
int monitor_pid_filtered(DWORD pid, DLLWATCH_FILTER filter);
int monitor_name_filtered(
    const char *process_name,
    DLLWATCH_FILTER filter
);

#endif
