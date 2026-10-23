#define INITGUID

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <tdh.h>
#include <stdlib.h>
#include <string.h>
#define DLLWATCH_LOGGER_NAME "DllWatchKernelSession"

static const GUID DLLWATCH_SESSION_GUID =
{
    0x8d60c1f5,
    0x71f2,
    0x4e88,
    {0xa7, 0x12, 0x42, 0x55, 0x91, 0x19, 0x73, 0x01}
};

#ifdef _MSC_VER
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#endif

static TRACEHANDLE session_handle = 0;
static TRACEHANDLE trace_handle = 0;
static DWORD g_target_pid = 0;

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
static void WINAPI event_callback(PEVENT_RECORD event)
{
    if (event->EventHeader.EventDescriptor.Opcode != 10)
        return;
    
    if (g_target_pid != 0 &&
        event->EventHeader.ProcessId != g_target_pid)
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

    printf("\n[DLL LOAD]\n");

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

    printf(
      "DLL:     %ls\n",
      (wchar_t *)name_data
    );


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

int monitor_pid(DWORD target_pid)
{
    ULONG status;

    g_target_pid = target_pid;

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
        EVENT_TRACE_FLAG_IMAGE_LOAD;

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
            EVENT_TRACE_FLAG_IMAGE_LOAD;

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

    printf("[+] Monitoring DLL loads for PID %lu...\n\n",
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

    status = ProcessTrace(
        &trace_handle,
        1,
        NULL,
        NULL
    );

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