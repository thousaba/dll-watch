#define INITGUID

#include <windows.h>
#include <tlhelp32.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <limits.h>
#include <tdh.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include "etw_monitor.h"
#define DLLWATCH_LOGGER_NAME "DllWatchKernelSession"

static const GUID DLLWATCH_SESSION_GUID =
{
    0x8d60c1f5,
    0x71f2,
    0x4e88,
    {0xa7, 0x12, 0x42, 0x55, 0x91, 0x19, 0x73, 0x01}
};

/* Classic kernel event class GUIDs; opcodes overlap across event classes. */
static const GUID PROCESS_EVENT_GUID =
{
    0x3d6fa8d0, 0xfe05, 0x11d0,
    {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}
};

static const GUID IMAGE_EVENT_GUID =
{
    0x2cb15d1d, 0x5fc1, 0x11d2,
    {0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18}
};


#ifdef _MSC_VER
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#endif

static TRACEHANDLE session_handle = 0;
static TRACEHANDLE trace_handle = 0;
static volatile LONG g_target_pid = 0;
static char g_target_name[MAX_PATH];
static DLLWATCH_FILTER g_event_filter = DLLWATCH_FILTER_ALL;
static DWORD g_target_pids[1024];
static DWORD g_target_pid_count = 0;
static SRWLOCK g_target_pid_lock = SRWLOCK_INIT;
static volatile LONG g_process_watcher_active = 0;

#define MAX_PENDING_FILE_OPS 1024
#define MAX_LIFECYCLE_RECORDS 4096
#define STATUS_OBJECT_NAME_NOT_FOUND_VALUE 0xC0000034UL

typedef struct _DLL_LIFECYCLE_RECORD {
    DWORD pid;
    ULONGLONG image_base;
    ULONGLONG load_timestamp;
    WCHAR *path;
    SYSTEMTIME loaded_at;
} DLL_LIFECYCLE_RECORD;

typedef struct _PENDING_FILE_OP {
    ULONGLONG irp;
    DWORD pid;
    WCHAR *path;
} PENDING_FILE_OP;

static PENDING_FILE_OP g_pending_file_ops[MAX_PENDING_FILE_OPS];
static ULONG g_pending_file_cursor = 0;
static DLL_LIFECYCLE_RECORD g_lifecycle_records[MAX_LIFECYCLE_RECORDS];

static int get_property(
    PEVENT_RECORD event,
    const wchar_t *property_name,
    BYTE **buffer,
    ULONG *buffer_size
);

static int get_process_image_path(
    DWORD pid,
    char *image_path,
    DWORD path_size
)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (process == NULL)
        return 0;

    DWORD length = path_size;
    BOOL success = QueryFullProcessImageNameA(process, 0, image_path, &length);
    CloseHandle(process);

    return success != FALSE;
}

static int get_u64_property(
    PEVENT_RECORD event,
    const wchar_t *property_name,
    ULONGLONG *value
)
{
    BYTE *data = NULL;
    ULONG size = 0;

    if (!get_property(event, property_name, &data, &size))
        return 0;

    if (size == sizeof(ULONG64))
        memcpy(value, data, sizeof(ULONG64));
    else if (size == sizeof(ULONG)) {
        ULONG value32;
        memcpy(&value32, data, sizeof(value32));
        *value = value32;
    } else {
        free(data);
        return 0;
    }

    free(data);
    return 1;
}

static void print_wide_utf8_raw(const WCHAR *value)
{
    if (value == NULL)
        return;

    int bytes_needed = WideCharToMultiByte(
        CP_UTF8,
        0,
        value,
        -1,
        NULL,
        0,
        NULL,
        NULL
    );

    if (bytes_needed <= 0)
        return;

    char *utf8 = malloc((size_t)bytes_needed);
    if (utf8 == NULL)
        return;

    if (WideCharToMultiByte(
            CP_UTF8,
            0,
            value,
            -1,
            utf8,
            bytes_needed,
            NULL,
            NULL) > 0)
        fputs(utf8, stdout);

    free(utf8);
}

static void print_wide_utf8(const WCHAR *value)
{
    static WCHAR drive_targets[26][MAX_PATH];
    static int drive_targets_initialized = 0;

    if (value == NULL)
        return;

    if (!drive_targets_initialized) {
        DWORD logical_drives = GetLogicalDrives();
        for (WCHAR letter = L'A'; letter <= L'Z'; letter++) {
            DWORD bit = 1UL << (letter - L'A');
            if ((logical_drives & bit) == 0)
                continue;

            WCHAR drive_name[] = {letter, L':', L'\0'};
            QueryDosDeviceW(drive_name,
                            drive_targets[letter - L'A'],
                            MAX_PATH);
        }
        drive_targets_initialized = 1;
    }

    if (wcsncmp(value, L"\\Device\\", 8) == 0) {
        for (WCHAR letter = L'A'; letter <= L'Z'; letter++) {
            const WCHAR *device_target = drive_targets[letter - L'A'];
            size_t prefix_length = wcslen(device_target);
            if (prefix_length == 0 ||
                _wcsnicmp(value, device_target, prefix_length) != 0 ||
                (value[prefix_length] != L'\\' &&
                 value[prefix_length] != L'\0'))
                continue;

            size_t suffix_length = wcslen(value + prefix_length);
            WCHAR *dos_path = malloc((suffix_length + 3) * sizeof(WCHAR));
            if (dos_path != NULL) {
                dos_path[0] = letter;
                dos_path[1] = L':';
                memcpy(dos_path + 2, value + prefix_length,
                       (suffix_length + 1) * sizeof(WCHAR));
                print_wide_utf8_raw(dos_path);
                free(dos_path);
                return;
            }
            break;
        }
    }
    print_wide_utf8_raw(value);
}

static void save_pending_file_op(ULONGLONG irp, DWORD pid, WCHAR *path)
{
    ULONG slot = g_pending_file_cursor++ % MAX_PENDING_FILE_OPS;

    for (ULONG i = 0; i < MAX_PENDING_FILE_OPS; i++) {
        ULONG candidate = (slot + i) % MAX_PENDING_FILE_OPS;
        if (g_pending_file_ops[candidate].irp == irp &&
            g_pending_file_ops[candidate].pid == pid) {
            slot = candidate;
            break;
        }
        if (g_pending_file_ops[candidate].path == NULL) {
            slot = candidate;
            break;
        }
    }

    free(g_pending_file_ops[slot].path);
    g_pending_file_ops[slot].irp = irp;
    g_pending_file_ops[slot].pid = pid;
    g_pending_file_ops[slot].path = path;
}

static WCHAR *take_pending_file_op(ULONGLONG irp, DWORD pid)
{
    for (ULONG i = 0; i < MAX_PENDING_FILE_OPS; i++) {
        PENDING_FILE_OP *pending = &g_pending_file_ops[i];
        if (pending->path != NULL && pending->irp == irp && pending->pid == pid) {
            WCHAR *path = pending->path;
            pending->path = NULL;
            pending->irp = 0;
            pending->pid = 0;
            return path;
        }
    }
    return NULL;
}

static int is_dll_path(const WCHAR *path)
{
    size_t length = wcslen(path);
    if (length < 4 || path[length - 4] != L'.')
        return 0;

    return towlower(path[length - 3]) == L'd' &&
           towlower(path[length - 2]) == L'l' &&
           towlower(path[length - 1]) == L'l';
}

static int process_name_matches(const char *image_path, const char *target_name)
{
    const char *base = strrchr(image_path, '\\');
    const char *target_base = strrchr(target_name, '\\');
    size_t image_len;
    size_t target_len;

    if (base != NULL)
        image_path = base + 1;
    base = strrchr(image_path, '/');
    if (base != NULL)
        image_path = base + 1;

    if (target_base != NULL)
        target_name = target_base + 1;
    target_base = strrchr(target_name, '/');
    if (target_base != NULL)
        target_name = target_base + 1;

    image_len = strlen(image_path);
    target_len = strlen(target_name);
    if (image_len >= 4 && _stricmp(image_path + image_len - 4, ".exe") == 0)
        image_len -= 4;
    if (target_len >= 4 && _stricmp(target_name + target_len - 4, ".exe") == 0)
        target_len -= 4;

    return image_len == target_len &&
           _strnicmp(image_path, target_name, image_len) == 0;
}

static int add_target_pid(DWORD pid)
{
    int added = 0;
    AcquireSRWLockExclusive(&g_target_pid_lock);
    for (DWORD i = 0; i < g_target_pid_count; i++) {
        if (g_target_pids[i] == pid) {
            ReleaseSRWLockExclusive(&g_target_pid_lock);
            return 0;
        }
    }

    if (g_target_pid_count >= sizeof(g_target_pids) / sizeof(g_target_pids[0])) {
        ReleaseSRWLockExclusive(&g_target_pid_lock);
        return 0;
    }

    g_target_pids[g_target_pid_count++] = pid;
    added = 1;
    ReleaseSRWLockExclusive(&g_target_pid_lock);
    return added;
}

static int is_target_pid(DWORD pid)
{
    int found = 0;
    AcquireSRWLockShared(&g_target_pid_lock);
    for (DWORD i = 0; i < g_target_pid_count; i++) {
        if (g_target_pids[i] == pid)
            found = 1;
    }
    ReleaseSRWLockShared(&g_target_pid_lock);
    return found;
}

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
    filetime.dwLowDateTime = (DWORD)(timestamp & 0xFFFFFFFFULL);
    filetime.dwHighDateTime = (DWORD)(timestamp >> 32);
    SYSTEMTIME utc_time;
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

static int event_provider_is(PEVENT_RECORD event, const GUID *provider_guid)
{
    return IsEqualGUID(&event->EventHeader.ProviderId, provider_guid);
}

static WCHAR *copy_wide_string(const WCHAR *value)
{
    size_t length = wcslen(value) + 1;
    WCHAR *copy = malloc(length * sizeof(WCHAR));
    if (copy != NULL)
        memcpy(copy, value, length * sizeof(WCHAR));
    return copy;
}

static void handle_lifecycle_event(
    DWORD pid,
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
    printf("\n[DLL LIFECYCLE]\nPID: %lu\n",
           (unsigned long)pid);
    char process_path[MAX_PATH];
    if (get_process_image_path(pid, process_path, sizeof(process_path)))
        printf("Process: %s\n", process_path);
    else
        printf("Process: <unavailable>\n");
    printf("Base: 0x%llX\nDLL: ", (unsigned long long)image_base);
    print_wide_utf8(path);
    printf("\n");

    if (match == MAX_LIFECYCLE_RECORDS) {
        printf("Loaded: <before monitoring or unmatched>\n"
               "Unloaded: ");
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

static void add_running_processes_by_name(void)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[WARN] Could not enumerate running processes: %lu\n",
                GetLastError());
        return;
    }

    PROCESSENTRY32 entry = {0};
    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            if (process_name_matches(entry.szExeFile, g_target_name) &&
                add_target_pid(entry.th32ProcessID)) {
                printf("[+] Found %s -> PID %lu\n",
                       g_target_name,
                       (unsigned long)entry.th32ProcessID);
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

static DWORD WINAPI process_watcher_thread(LPVOID context)
{
    UNREFERENCED_PARAMETER(context);

    while (InterlockedCompareExchange(&g_process_watcher_active, 1, 1) == 1) {
        add_running_processes_by_name();
        Sleep(100);
    }

    return 0;
}

static void WINAPI event_callback(PEVENT_RECORD event)
{
    UCHAR opcode = event->EventHeader.EventDescriptor.Opcode;

    if (g_target_name[0] != '\0' &&
        event_provider_is(event, &PROCESS_EVENT_GUID) && opcode == 1) {
        char image_path[MAX_PATH];
        DWORD pid = event->EventHeader.ProcessId;

        if (pid != 0 &&
            get_process_image_path(pid, image_path, sizeof(image_path)) &&
            process_name_matches(image_path, g_target_name) &&
            add_target_pid(pid)) {
            printf("[+] Found %s -> PID %lu\n",
                   g_target_name, (unsigned long)pid);
            fflush(stdout);
        }
        return;
    }

    LONG target_pid = InterlockedCompareExchange(&g_target_pid, 0, 0);
    if (g_target_name[0] != '\0') {
        if (!is_target_pid(event->EventHeader.ProcessId))
            return;
    } else if (target_pid != 0 &&
               event->EventHeader.ProcessId != (ULONG)target_pid) {
        return;
    }

    if (opcode == 64) {
        if (g_event_filter != DLLWATCH_FILTER_NOT_FOUND)
            return;

        ULONGLONG irp = 0;
        BYTE *path_data = NULL;
        ULONG path_size = 0;

        if (get_u64_property(event, L"IrpPtr", &irp) &&
            get_property(event, L"OpenPath", &path_data, &path_size) &&
            path_size >= sizeof(WCHAR)) {
            WCHAR *path = malloc(path_size + sizeof(WCHAR));
            if (path != NULL) {
                memcpy(path, path_data, path_size);
                path[path_size / sizeof(WCHAR)] = L'\0';
                save_pending_file_op(irp, event->EventHeader.ProcessId, path);
            }
        }
        free(path_data);
        return;
    }

    if (opcode == 76) {
        if (g_event_filter != DLLWATCH_FILTER_NOT_FOUND)
            return;

        ULONGLONG irp = 0;
        ULONGLONG nt_status = 0;
        if (get_u64_property(event, L"IrpPtr", &irp) &&
            get_u64_property(event, L"NtStatus", &nt_status)) {
            WCHAR *path = take_pending_file_op(irp, event->EventHeader.ProcessId);
            if ((ULONG)nt_status == STATUS_OBJECT_NAME_NOT_FOUND_VALUE &&
                path != NULL && is_dll_path(path)) {
                printf("\n[NAME NOT FOUND]\n");
                printf("PID:  %lu\n", (unsigned long)event->EventHeader.ProcessId);
                printf("Path: ");
                print_wide_utf8(path != NULL ? path : L"<path unavailable>");
                printf("\n");
            }
            free(path);
        }
        return;
    }

    /* Process stop events share opcode 2 with image unload events. */
    if (!event_provider_is(event, &IMAGE_EVENT_GUID))
        return;

    if (opcode != 10 && opcode != 2)
        return;
    if (g_event_filter == DLLWATCH_FILTER_NOT_FOUND)
        return;
    if (g_event_filter == DLLWATCH_FILTER_UNLOAD && opcode != 2)
        return;
    if (g_event_filter == DLLWATCH_FILTER_ALL && opcode != 10)
        return;

    BYTE *pid_data = NULL;
    BYTE *base_data = NULL;
    BYTE *size_data = NULL;
    BYTE *name_data = NULL;

    ULONG pid_size = 0;
    ULONG base_size = 0;
    ULONG image_size_size = 0;
    ULONG name_size = 0;

    if (!get_property(
            event,
            L"ProcessId",
            &pid_data,
            &pid_size))
        goto cleanup;

    if (!get_property(
            event,
            L"ImageBase",
            &base_data,
            &base_size))
        goto cleanup;

    if (!get_property(
            event,
            L"ImageSize",
            &size_data,
            &image_size_size))
        goto cleanup;

    if (!get_property(
            event,
            L"FileName",
            &name_data,
            &name_size))
        goto cleanup;

    ULONG pid = *(ULONG *)pid_data;

    ULONGLONG image_base = 0;
    ULONGLONG image_size = 0;

    if (base_size == sizeof(ULONG64))
        image_base = *(ULONG64 *)base_data;
    else if (base_size == sizeof(ULONG))
        image_base = *(ULONG *)base_data;

    if (image_size_size == sizeof(ULONG64))
        image_size = *(ULONG64 *)size_data;
    else if (image_size_size == sizeof(ULONG))
        image_size = *(ULONG *)size_data;

    if (g_event_filter == DLLWATCH_FILTER_LIFECYCLE) {
        handle_lifecycle_event(
            pid,
            image_base,
            (WCHAR *)name_data,
            opcode,
            (ULONGLONG)event->EventHeader.TimeStamp.QuadPart
        );
        goto cleanup;
    }

    char process_path[MAX_PATH];
    DWORD process_path_size = MAX_PATH;

    int have_process =
        get_process_image_path(
            pid,
            process_path,
            process_path_size
        );

    printf("\n[%s]\n", opcode == 10 ? "DLL LOAD" : "DLL UNLOAD");

    printf(
        "PID:     %lu\n",
        (unsigned long)pid
    );

    if (have_process)
        printf("Process: %s\n", process_path);
    else
        printf("Process: <unavailable>\n");

    printf(
        "Base:    0x%llX\n",
        (unsigned long long)image_base
    );

    printf(
        "Size:    %llu bytes\n",
        (unsigned long long)image_size
    );

    printf("DLL:     ");
    print_wide_utf8((WCHAR *)name_data);
    printf("\n");

cleanup:
    free(pid_data);
    free(base_data);
    free(size_data);
    free(name_data);
}
static int get_property(
    PEVENT_RECORD event,
    const wchar_t *property_name,
    BYTE **buffer,
    ULONG *buffer_size
)
{
    PROPERTY_DATA_DESCRIPTOR descriptor = {0};

    descriptor.PropertyName = (ULONGLONG)property_name;
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG size = 0;

    ULONG status = TdhGetPropertySize(
        event,
        0,
        NULL,
        1,
        &descriptor,
        &size
    );

    if (status != ERROR_SUCCESS) {
        fprintf(stderr,
                "[ERROR] TdhGetPropertySize failed for %ls: %lu\n",
                property_name,
                status);
        return 0;
    }

    BYTE *data = malloc(size);

    if (data == NULL) {
        fprintf(stderr, "[ERROR] Out of memory.\n");
        return 0;
    }

    status = TdhGetProperty(
        event,
        0,
        NULL,
        1,
        &descriptor,
        size,
        data
    );

    if (status != ERROR_SUCCESS) {
        fprintf(stderr,
                "[ERROR] TdhGetProperty failed for %ls: %lu\n",
                property_name,
                status);

        free(data);
        return 0;
    }

    *buffer = data;
    *buffer_size = size;

    return 1;
}

static int monitor_pid_with_filter(DWORD target_pid, DLLWATCH_FILTER filter)
{
    ULONG status;

    SetConsoleOutputCP(CP_UTF8);
    g_event_filter = filter;
    if (g_target_name[0] != '\0')
        InterlockedExchange(&g_target_pid, 0);
    else
        InterlockedExchange(&g_target_pid, (LONG)target_pid);

    ULONG properties_size =
        sizeof(EVENT_TRACE_PROPERTIES) +
        sizeof(DLLWATCH_LOGGER_NAME);

    EVENT_TRACE_PROPERTIES *properties =
        calloc(1, properties_size);

    if (properties == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed.\n");
        return 1;
    }

    properties->Wnode.BufferSize = properties_size;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1;
    properties->Wnode.Guid = DLLWATCH_SESSION_GUID;

    properties->LogFileMode =
        EVENT_TRACE_REAL_TIME_MODE |
        EVENT_TRACE_SYSTEM_LOGGER_MODE;

    properties->EnableFlags =
        EVENT_TRACE_FLAG_IMAGE_LOAD |
        EVENT_TRACE_FLAG_PROCESS |
        EVENT_TRACE_FLAG_FILE_IO |
        EVENT_TRACE_FLAG_FILE_IO_INIT;

    properties->LoggerNameOffset =
        sizeof(EVENT_TRACE_PROPERTIES);

    status = StartTrace(
        &session_handle,
        DLLWATCH_LOGGER_NAME,
        properties
    );

    if (status == ERROR_ALREADY_EXISTS) {
        printf("[!] Previous dll-watch ETW session found. Cleaning it up...\n");

        ULONG stop_status = ControlTrace(
            0,
            DLLWATCH_LOGGER_NAME,
            properties,
            EVENT_TRACE_CONTROL_STOP
        );

        if (stop_status != ERROR_SUCCESS &&
            stop_status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            fprintf(stderr,
                    "[ERROR] Could not stop stale session: %lu\n",
                    stop_status);

            free(properties);
            return 1;
        }

        memset(properties, 0, properties_size);

        properties->Wnode.BufferSize = properties_size;
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->Wnode.ClientContext = 1;
        properties->Wnode.Guid = DLLWATCH_SESSION_GUID;

        properties->LogFileMode =
            EVENT_TRACE_REAL_TIME_MODE |
            EVENT_TRACE_SYSTEM_LOGGER_MODE;

        properties->EnableFlags =
            EVENT_TRACE_FLAG_IMAGE_LOAD |
            EVENT_TRACE_FLAG_PROCESS |
            EVENT_TRACE_FLAG_FILE_IO |
            EVENT_TRACE_FLAG_FILE_IO_INIT;

        properties->LoggerNameOffset =
            sizeof(EVENT_TRACE_PROPERTIES);

        status = StartTrace(
            &session_handle,
            DLLWATCH_LOGGER_NAME,
            properties
        );
    }

    if (status != ERROR_SUCCESS) {
        fprintf(stderr,
                "[ERROR] StartTrace failed: %lu\n",
                status);

        free(properties);
        return 1;
    }

    if (g_target_name[0] != '\0')
        add_running_processes_by_name();

    if (g_target_name[0] != '\0' && g_target_pid_count == 0)
        printf("[+] Waiting for process %s to start...\n\n", g_target_name);
    else if (g_target_name[0] == '\0')
        printf("[+] Monitoring DLL activity for PID %lu...\n\n",
               (unsigned long)target_pid);

    EVENT_TRACE_LOGFILE logfile = {0};

    logfile.LoggerName = DLLWATCH_LOGGER_NAME;

    logfile.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD;

    logfile.EventRecordCallback = event_callback;

    trace_handle = OpenTrace(&logfile);

    if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr,
                "[ERROR] OpenTrace failed: %lu\n",
                GetLastError());

        ControlTrace(
            session_handle,
            DLLWATCH_LOGGER_NAME,
            properties,
            EVENT_TRACE_CONTROL_STOP
        );

        free(properties);
        return 1;
    }

    HANDLE process_watch_thread = NULL;
    if (g_target_name[0] != '\0') {
        InterlockedExchange(&g_process_watcher_active, 1);
        process_watch_thread = CreateThread(
            NULL,
            0,
            process_watcher_thread,
            NULL,
            0,
            NULL
        );
        if (process_watch_thread == NULL) {
            InterlockedExchange(&g_process_watcher_active, 0);
            fprintf(stderr, "[WARN] Process watcher thread could not be started.\n");
        }
    }

    status = ProcessTrace(
        &trace_handle,
        1,
        NULL,
        NULL
    );

    InterlockedExchange(&g_process_watcher_active, 0);
    if (process_watch_thread != NULL) {
        WaitForSingleObject(process_watch_thread, INFINITE);
        CloseHandle(process_watch_thread);
    }

    if (status != ERROR_SUCCESS) {
        fprintf(stderr,
                "[ERROR] ProcessTrace failed: %lu\n",
                status);
    }

    CloseTrace(trace_handle);

    ControlTrace(
        session_handle,
        DLLWATCH_LOGGER_NAME,
        properties,
        EVENT_TRACE_CONTROL_STOP
    );

    free(properties);

    return 0;
}

int monitor_pid(DWORD pid)
{
    g_target_name[0] = '\0';
    return monitor_pid_with_filter(pid, DLLWATCH_FILTER_ALL);
}

int monitor_pid_filtered(DWORD pid, DLLWATCH_FILTER filter)
{
    g_target_name[0] = '\0';
    return monitor_pid_with_filter(pid, filter);
}

int monitor_name(const char *process_name)
{
    return monitor_name_filtered(
        process_name,
        DLLWATCH_FILTER_ALL
    );
}

int monitor_name_filtered(
    const char *process_name,
    DLLWATCH_FILTER filter
)
{
    strncpy(g_target_name, process_name, sizeof(g_target_name) - 1);
    g_target_name[sizeof(g_target_name) - 1] = '\0';
    g_target_pid_count = 0;
    return monitor_pid_with_filter(0, filter);
}
