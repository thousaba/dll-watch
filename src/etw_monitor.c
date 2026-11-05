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
#include "dll_path.h"
#include "dll_lifecycle.h"
#include "dll_resolution.h"
#include "dll_signature_cache.h"
#include "dll_async.h"

#define DLLWATCH_LOGGER_NAME "DllWatchKernelSession"

static const GUID DLLWATCH_SESSION_GUID =
{
    0x8d60c1f5,
    0x71f2,
    0x4e88,
    {0xa7, 0x12, 0x42, 0x55, 0x91, 0x19, 0x73, 0x01}
};

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
static volatile LONG g_shutdown_requested = 0;

static BOOL WINAPI dllwatch_ctrl_handler(DWORD ctrl_type)
{
    if (ctrl_type != CTRL_C_EVENT &&
        ctrl_type != CTRL_BREAK_EVENT) {
        return FALSE;
    }

    /* Only the first Ctrl+C should stop the ETW session. */
    if (InterlockedCompareExchange(
            &g_shutdown_requested, 1, 0) == 0) {

        struct {
            EVENT_TRACE_PROPERTIES props;
            char logger_name[sizeof(DLLWATCH_LOGGER_NAME)];
        } stop_info = {0};

        stop_info.props.Wnode.BufferSize = sizeof(stop_info);
        stop_info.props.Wnode.Guid = DLLWATCH_SESSION_GUID;
        stop_info.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        stop_info.props.LoggerNameOffset =
            sizeof(EVENT_TRACE_PROPERTIES);

        ULONG result = ControlTrace(
            0,
            DLLWATCH_LOGGER_NAME,
            &stop_info.props,
            EVENT_TRACE_CONTROL_STOP
        );

        if (result != ERROR_SUCCESS &&
            result != ERROR_WMI_INSTANCE_NOT_FOUND) {
            InterlockedExchange(&g_shutdown_requested, 0);
            return FALSE;
        }
    }

    return TRUE;
}
#define MAX_PENDING_FILE_OPS 1024

#define STATUS_OBJECT_NAME_NOT_FOUND_VALUE 0xC0000034UL

typedef struct _PENDING_FILE_OP {
    ULONGLONG irp;
    DWORD pid;
    WCHAR *path;
} PENDING_FILE_OP;

static PENDING_FILE_OP g_pending_file_ops[MAX_PENDING_FILE_OPS];
static ULONG g_pending_file_cursor = 0;
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

static int event_provider_is(PEVENT_RECORD event, const GUID *provider_guid)
{
    return IsEqualGUID(&event->EventHeader.ProviderId, provider_guid);
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
        if (g_event_filter != DLLWATCH_FILTER_NOT_FOUND &&
            g_event_filter != DLLWATCH_FILTER_RESOLUTION)
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
        if (g_event_filter != DLLWATCH_FILTER_NOT_FOUND &&
            g_event_filter != DLLWATCH_FILTER_RESOLUTION)
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
                dll_path_print(path != NULL ? path : L"<path unavailable>");
                printf("\n");
                dll_path_print_classification(event->EventHeader.ProcessId, path);
                if (g_event_filter == DLLWATCH_FILTER_RESOLUTION)
                    dll_resolution_record_lookup(
                        event->EventHeader.ProcessId,
                        path,
                        (ULONGLONG)event->EventHeader.TimeStamp.QuadPart
                    );
            }
            free(path);
        }
        return;
    }
    if (!event_provider_is(event, &IMAGE_EVENT_GUID))
        return;
    if (opcode != 10 && opcode != 2)
        return;
    if (g_event_filter == DLLWATCH_FILTER_NOT_FOUND)
        return;
    if (g_event_filter == DLLWATCH_FILTER_RESOLUTION && opcode != 10)
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
    char process_path[MAX_PATH];
    DWORD process_path_size = MAX_PATH;
    int have_process =
        get_process_image_path(
            pid,
            process_path,
            process_path_size
        );
    if (g_event_filter == DLLWATCH_FILTER_LIFECYCLE) {
        dll_lifecycle_handle_event(
            pid,
            have_process ? process_path : NULL,
            image_base,
            (WCHAR *)name_data,
            opcode,
            (ULONGLONG)event->EventHeader.TimeStamp.QuadPart
        );
        goto cleanup;
    }
      
    if (opcode == 10) {
    WCHAR normalized_path[32768] = {0};

    const WCHAR *source_path = (const WCHAR *)name_data;
    const WCHAR *job_path = source_path;

    if (dll_path_to_dos(
            source_path,
            normalized_path,
            sizeof(normalized_path) / sizeof(normalized_path[0]))) {
        job_path = normalized_path;
    }

    DLL_PATH_CLASSIFICATION classification =
        classify_dll_path(pid, source_path);

    DLLWATCH_IMAGE_JOB job = {0};

    job.pid = pid;
    job.image_base = image_base;
    job.image_size = image_size;

    job.timestamp =
        (ULONGLONG)event->EventHeader.TimeStamp.QuadPart;

    job.opcode = opcode;
    job.dll_path = (WCHAR *)job_path;
    job.have_process = have_process ? TRUE : FALSE;

        if (have_process) {
          snprintf(
            job.process_path,
            sizeof(job.process_path),
            "%s",
            process_path
        );
        }

        wcsncpy(
          job.location,
          classification.location,
          sizeof(job.location) / sizeof(WCHAR) - 1
        );

        wcsncpy(
          job.writable,
          classification.writable,
          sizeof(job.writable) / sizeof(WCHAR) - 1
        );

        if (!dll_async_submit(&job)) {
        fprintf(
            stderr,
            "[WARN] DLL event could not be queued. PID=%lu\n",
            (unsigned long)pid
        );
        }

        } else {
        printf("\n[DLL UNLOAD]\n");
        printf("PID: %lu\n", (unsigned long)pid);
        printf("Process: %s\n",
           have_process ? process_path : "<unavailable>");
        printf("Base: 0x%llX\n",
           (unsigned long long)image_base);
        printf("DLL: ");
        dll_path_print((WCHAR *)name_data);
        printf("\n");
        dll_path_print_classification(pid, (WCHAR *)name_data);
        }

        if (g_event_filter == DLLWATCH_FILTER_RESOLUTION && opcode == 10) {
          dll_resolution_correlate_load(
            pid,
            have_process ? process_path : NULL,
            (WCHAR *)name_data,
            (ULONGLONG)event->EventHeader.TimeStamp.QuadPart
            );
        }
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
    int use_async =
    filter == DLLWATCH_FILTER_ALL ||
    filter == DLLWATCH_FILTER_RESOLUTION;
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
        fprintf(stderr, "[ERROR] OpenTrace failed: %lu\n", GetLastError());
        ControlTrace(
            session_handle,
            DLLWATCH_LOGGER_NAME,
            properties,
            EVENT_TRACE_CONTROL_STOP
        );
        free(properties);
        return 1;
    }

    if (use_async && !dll_async_init()) {
        fprintf(stderr, "[ERROR] Async worker initialization failed.\n");
        CloseTrace(trace_handle);
        ControlTrace(
            session_handle,
            DLLWATCH_LOGGER_NAME,
            properties,
            EVENT_TRACE_CONTROL_STOP
        );
        free(properties);
        return 1;
    }

    InterlockedExchange(&g_shutdown_requested, 0);

    if (!SetConsoleCtrlHandler(dllwatch_ctrl_handler, TRUE)) {
      fprintf(stderr, "[ERROR] Could not register Ctrl+C handler.\n");

    CloseTrace(trace_handle);

    ControlTrace(
        session_handle,
        DLLWATCH_LOGGER_NAME,
        properties,
        EVENT_TRACE_CONTROL_STOP
    );

    if (use_async) {
        dll_async_shutdown();
    }

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
    LONG shutdown_requested =
    InterlockedCompareExchange(&g_shutdown_requested, 0, 0);

    if (status != ERROR_SUCCESS &&
    !(shutdown_requested &&
      status == ERROR_WMI_INSTANCE_NOT_FOUND)) {

    fprintf(stderr,
            "[ERROR] ProcessTrace failed: %lu\n",
            status);
    }

    CloseTrace(trace_handle);

    if (!shutdown_requested) {
    ControlTrace(
        session_handle,
        DLLWATCH_LOGGER_NAME,
        properties,
        EVENT_TRACE_CONTROL_STOP
    );
    }

    if (use_async) {
    dll_async_shutdown();
    }

    SetConsoleCtrlHandler(dllwatch_ctrl_handler, FALSE);

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
