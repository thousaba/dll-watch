
#include <windows.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "dll_async.h"
#include "dll_signature_cache.h"

#define DLL_ASYNC_QUEUE_CAPACITY 1024

static DLLWATCH_IMAGE_JOB g_queue[DLL_ASYNC_QUEUE_CAPACITY];
static CRITICAL_SECTION g_queue_lock;
static CONDITION_VARIABLE g_queue_cond;
static HANDLE g_worker_thread = NULL;
static size_t g_head = 0;
static size_t g_tail = 0;
static size_t g_count = 0;
static ULONGLONG g_dropped_jobs = 0;
static ULONGLONG g_submitted_jobs = 0;
static ULONGLONG g_processed_jobs = 0;
static size_t g_peak_queue = 0;
static int g_initialized = 0;
static int g_stopping = 0;
static LARGE_INTEGER g_qpc_frequency;
static LARGE_INTEGER g_enqueued_at[DLL_ASYNC_QUEUE_CAPACITY];
static double g_total_queue_ms = 0;
static double g_total_processing_ms = 0;
static double g_total_e2e_ms = 0;
static double g_max_queue_ms = 0;
static double g_max_processing_ms = 0;

static char *wide_to_utf8(const WCHAR *value)
{
    if (!value)
        return NULL;

    int size = WideCharToMultiByte(
        CP_UTF8, 0, value, -1,
        NULL, 0, NULL, NULL
    );

    if (size <= 0)
        return NULL;

    char *result = malloc((size_t)size);

    if (!result)
        return NULL;

    if (!WideCharToMultiByte(
            CP_UTF8, 0, value, -1,
            result, size, NULL, NULL)) {
        free(result);
        return NULL;
    }

    return result;
}


static const char *signature_status_name(
    DLL_SIGNATURE_STATUS status)
{
    switch (status) {
        case DLL_SIGNATURE_VALID:
            return "valid";

        case DLL_SIGNATURE_UNSIGNED:
            return "unsigned";

        default:
            return "failed";
    }
}


static const char *signature_type_name(
    DLL_SIGNATURE_TYPE type)
{
    switch (type) {
        case DLL_SIGNATURE_TYPE_EMBEDDED:
            return "embedded";

        case DLL_SIGNATURE_TYPE_CATALOG:
            return "catalog";

        case DLL_SIGNATURE_TYPE_NONE:
            return "none";

        default:
            return "unknown";
    }
}



static void process_signature_job(const DLLWATCH_IMAGE_JOB *job)
{
    DLL_SIGNATURE_INFO signature = {0};

    DLL_SIGNATURE_CACHE_RESULT cache_result =
        DLL_SIGNATURE_CACHE_BYPASS;

    int success = dll_signature_cache_inspect(
        job->dll_path,
        &signature,
        &cache_result
    );

    char *dll_path = wide_to_utf8(job->dll_path);
    char *location = wide_to_utf8(job->location);
    char *writable = wide_to_utf8(job->writable);

    char *signer = success
        ? wide_to_utf8(signature.signer)
        : NULL;

    printf(
        "\n[DLL LOAD]\n"
        "PID:       %lu\n"
        "Process:   %s\n"
        "Base:      0x%llX\n"
        "Size:      %llu bytes\n"
        "DLL:       %s\n"
        "Location:  %s\n"
        "Writable:  %s\n"
        "Signature: %s\n"
        "Type:      %s\n"
        "Signer:    %s\n",
        (unsigned long)job->pid,
        job->have_process
            ? job->process_path
            : "<unavailable>",
        (unsigned long long)job->image_base,
        (unsigned long long)job->image_size,
        dll_path ? dll_path : "<unavailable>",
        location ? location : "unknown",
        writable ? writable : "unknown",
        success
            ? signature_status_name(signature.status)
            : "inspection unavailable",
        success
            ? signature_type_name(signature.type)
            : "unknown",
        signer && signer[0]
            ? signer
            : "none"
    );

    free(dll_path);
    free(location);
    free(writable);
    free(signer);
}



DWORD WINAPI dll_async_worker(LPVOID context)
{
    (void)context;

    for (;;) {
        DLLWATCH_IMAGE_JOB job;

        LARGE_INTEGER queued_at;
        LARGE_INTEGER started_at;
        LARGE_INTEGER finished_at;

        EnterCriticalSection(&g_queue_lock);

        while (g_count == 0 && !g_stopping) {
            if (!SleepConditionVariableCS(
                    &g_queue_cond,
                    &g_queue_lock,
                    INFINITE)) {
                g_stopping = 1;
                break;
            }
        }

        if (g_count == 0 && g_stopping) {
            LeaveCriticalSection(&g_queue_lock);
            break;
        }

        job = g_queue[g_head];
        queued_at = g_enqueued_at[g_head];
        QueryPerformanceCounter(&started_at);
        g_queue[g_head].dll_path = NULL;

        g_head = (g_head + 1) % DLL_ASYNC_QUEUE_CAPACITY;
        g_count--;

        LeaveCriticalSection(&g_queue_lock);
        process_signature_job(&job);
        QueryPerformanceCounter(&finished_at);
        free(job.dll_path);

        double frequency = (double)g_qpc_frequency.QuadPart;

        double queue_ms =
         (double)(started_at.QuadPart - queued_at.QuadPart)
          * 1000.0 / frequency;

        double processing_ms =
          (double)(finished_at.QuadPart - started_at.QuadPart)
          * 1000.0 / frequency;

        double e2e_ms =
          (double)(finished_at.QuadPart - queued_at.QuadPart)
          * 1000.0 / frequency;

        EnterCriticalSection(&g_queue_lock);

        g_processed_jobs++;
        g_total_queue_ms += queue_ms;
        g_total_processing_ms += processing_ms;
        g_total_e2e_ms += e2e_ms;

        if (queue_ms > g_max_queue_ms)
          g_max_queue_ms = queue_ms;

        if (processing_ms > g_max_processing_ms)
          g_max_processing_ms = processing_ms;

        LeaveCriticalSection(&g_queue_lock);

        }

        return 0;
}


static unsigned __stdcall worker_entry(void *context)
{
    return (unsigned)dll_async_worker(context);
}


int dll_async_init(void)
{
    if (g_initialized)
        return 1;

    memset(g_queue, 0, sizeof(g_queue));

    g_head = 0;
    g_tail = 0;
    g_count = 0;
    g_dropped_jobs = 0;
    g_stopping = 0;
    g_submitted_jobs = 0;
    g_processed_jobs = 0;
    g_peak_queue = 0;
    g_total_queue_ms = 0;
    g_total_processing_ms = 0;
    g_total_e2e_ms = 0;

    g_max_queue_ms = 0;
    g_max_processing_ms = 0;

    if (!QueryPerformanceFrequency(&g_qpc_frequency)) {
      return 0;
    }

    InitializeCriticalSection(&g_queue_lock);
    InitializeConditionVariable(&g_queue_cond);

    uintptr_t thread_handle = _beginthreadex(
        NULL,
        0,
        worker_entry,
        NULL,
        0,
        NULL
    );

    if (!thread_handle) {
        DeleteCriticalSection(&g_queue_lock);
        return 0;
    }

    g_worker_thread = (HANDLE)thread_handle;
    g_initialized = 1;

    return 1;
}


int dll_async_submit(DLLWATCH_IMAGE_JOB *job)
{
    if (!g_initialized || !job ||
        !job->dll_path || !job->dll_path[0]) {
        return 0;
    }

    size_t length = wcslen(job->dll_path);

    if (length >= 32768)
        return 0;

    WCHAR *path_copy = malloc((length + 1) * sizeof(WCHAR));

    if (!path_copy)
        return 0;

    memcpy(
        path_copy,
        job->dll_path,
        (length + 1) * sizeof(WCHAR)
    );

    EnterCriticalSection(&g_queue_lock);

    if (g_stopping || g_count == DLL_ASYNC_QUEUE_CAPACITY) {
        g_dropped_jobs++;

        LeaveCriticalSection(&g_queue_lock);
        free(path_copy);

        return 0;
    }

    DLLWATCH_IMAGE_JOB copy = *job;
    copy.dll_path = path_copy;

    g_queue[g_tail] = copy;

    QueryPerformanceCounter(&g_enqueued_at[g_tail]);

    g_tail = (g_tail + 1) % DLL_ASYNC_QUEUE_CAPACITY;
    g_count++;

    g_submitted_jobs++;

    if (g_count > g_peak_queue) {
      g_peak_queue = g_count;
    }

    LeaveCriticalSection(&g_queue_lock);

    WakeConditionVariable(&g_queue_cond);

    return 1;
}


void dll_async_shutdown(void)
{
    if (!g_initialized)
        return;

    EnterCriticalSection(&g_queue_lock);

    g_stopping = 1;

    LeaveCriticalSection(&g_queue_lock);

    WakeAllConditionVariable(&g_queue_cond);

    DWORD result = WaitForSingleObject(
        g_worker_thread,
        INFINITE
    );

    if (result != WAIT_OBJECT_0) {
        fprintf(stderr, "[ASYNC] Worker join failed.\n");
        return;
    }

    printf(
        "\n[ASYNC] Worker stopped. Dropped jobs: %llu\n",
        (unsigned long long)g_dropped_jobs
    );

    CloseHandle(g_worker_thread);

    g_worker_thread = NULL;
    g_initialized = 0;

    DeleteCriticalSection(&g_queue_lock);

    double processed = (double)g_processed_jobs;

    printf(
    "\n=== ASYNC WORKER STATS ===\n"
    "Submitted:         %llu\n"
    "Processed:         %llu\n"
    "Dropped:           %llu\n"
    "Peak queue:        %zu / %d\n"
    "\n"
    "Avg queue wait:    %.3f ms\n"
    "Max queue wait:    %.3f ms\n"
    "Avg processing:    %.3f ms\n"
    "Max processing:    %.3f ms\n"
    "Avg end-to-end:    %.3f ms\n",
    (unsigned long long)g_submitted_jobs,
    (unsigned long long)g_processed_jobs,
    (unsigned long long)g_dropped_jobs,
    g_peak_queue,
    DLL_ASYNC_QUEUE_CAPACITY,
    processed > 0 ? g_total_queue_ms / processed : 0,
    g_max_queue_ms,
    processed > 0 ? g_total_processing_ms / processed : 0,
    g_max_processing_ms,
    processed > 0 ? g_total_e2e_ms / processed : 0
    );

}

