#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "etw_monitor.h"

#ifdef _MSC_VER
#pragma comment(lib, "Psapi.lib")
#endif


static void print_help(void)
{
    printf("dll-watch - Windows DLL monitoring tool\n\n");
    printf("Usage:\n");
    printf("  dll-watch.exe -help\n");
    printf("  dll-watch.exe -processes\n");
    printf("  dll-watch.exe -pid <PID>\n");
    printf("  dll-watch.exe -name <PROCESS_NAME>\n");
    printf("  dll-watch.exe -modules <PID>\n");
    printf("  dll-watch.exe -modules-name <PROCESS_NAME>\n");
    printf("  dll-watch.exe -monitor-pid <PID>\n");
    printf("  dll-watch.exe -monitor-name <PROCESS_NAME>\n");
    printf("  dll-watch.exe -monitor-unload <PROCESS_NAME|PID>\n");
    printf("  dll-watch.exe -monitor-lifecycle <PROCESS_NAME|PID>\n");
    printf("  dll-watch.exe -monitor-name-not-found <PROCESS_NAME|PID>\n");
    printf("  dll-watch.exe -monitor-resolution <PROCESS_NAME|PID>\n");
}

static int name_equal(const char *a, const char *b)
{
    const char *name_a = a;
    const char *name_b = b;
    const char *separator;
    size_t len_a;
    size_t len_b;

    separator = strrchr(name_a, '\\');
    if (separator != NULL)
        name_a = separator + 1;
    separator = strrchr(name_a, '/');
    if (separator != NULL)
        name_a = separator + 1;

    separator = strrchr(name_b, '\\');
    if (separator != NULL)
        name_b = separator + 1;
    separator = strrchr(name_b, '/');
    if (separator != NULL)
        name_b = separator + 1;

    len_a = strlen(name_a);
    len_b = strlen(name_b);

    while (len_a >= 4 && _stricmp(name_a + len_a - 4, ".exe") == 0)
        len_a -= 4;
    while (len_b >= 4 && _stricmp(name_b + len_b - 4, ".exe") == 0)
        len_b -= 4;

    return len_a == len_b && _strnicmp(name_a, name_b, len_a) == 0;
}

static int get_process_image_path(DWORD pid, char *image_path, DWORD path_size)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL)
        return 0;

    int success = QueryFullProcessImageNameA(process, 0, image_path, &path_size);
    CloseHandle(process);
    return success;
}

static int process_id_exists(DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

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
    }

    CloseHandle(snapshot);
    return found;
}

static int list_processes(const char *filter_name, DWORD filter_pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[ERROR] Snapshot failed: %lu\n", GetLastError());
        return 1;
    }

    PROCESSENTRY32 entry = {0};
    entry.dwSize = sizeof(entry);
    if (!Process32First(snapshot, &entry)) {
        DWORD error = GetLastError();
        CloseHandle(snapshot);
        fprintf(stderr, "[ERROR] Process32First failed: %lu\n", error);
        return 1;
    }

    int found = 0;
    printf("%-8s %-8s %-24s %s\n", "PID", "PPID", "PROCESS", "IMAGE PATH");
    printf("--------------------------------------------------------------------------------\n");

    do {
        if (filter_pid != 0 && entry.th32ProcessID != filter_pid)
            continue;
        if (filter_name != NULL && !name_equal(entry.szExeFile, filter_name))
            continue;

        char image_path[MAX_PATH];
        if (get_process_image_path(entry.th32ProcessID, image_path, MAX_PATH)) {
            printf("%-8lu %-8lu %-24s %s\n",
                   (unsigned long)entry.th32ProcessID,
                   (unsigned long)entry.th32ParentProcessID,
                   entry.szExeFile,
                   image_path);
        } else {
            printf("%-8lu %-8lu %-24s %s\n",
                   (unsigned long)entry.th32ProcessID,
                   (unsigned long)entry.th32ParentProcessID,
                   entry.szExeFile,
                   "<unavailable>");
        }
        found = 1;
    } while (Process32Next(snapshot, &entry));

    DWORD error = GetLastError();
    CloseHandle(snapshot);

    if (!found) {
        fprintf(stderr, "[INFO] No matching process found.\n");
        return 1;
    }
    if (error != ERROR_NO_MORE_FILES)
        fprintf(stderr, "[WARN] Enumeration ended unexpectedly: %lu\n", error);

    return 0;
}


static int list_modules(DWORD pid)
{
    HANDLE process = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (process == NULL) {
        fprintf(stderr,
                "[ERROR] Cannot open process %lu. Error: %lu\n",
                (unsigned long)pid,
                GetLastError());
        return 1;
    }

    HMODULE initial_modules[256];
    HMODULE *modules = initial_modules;
    DWORD needed = 0;
    DWORD capacity = sizeof(initial_modules);

    if (!EnumProcessModules(
            process, modules, capacity, &needed)) {
        DWORD error = GetLastError();
        CloseHandle(process);
        fprintf(stderr,
                "[ERROR] EnumProcessModules failed: %lu\n",
                error);
        return 1;
    }

    if (needed > capacity) {
        modules = malloc(needed);

        if (modules == NULL) {
            CloseHandle(process);
            fprintf(stderr, "[ERROR] Out of memory.\n");
            return 1;
        }

        capacity = needed;

        if (!EnumProcessModules(
                process, modules, capacity, &needed)) {
            DWORD error = GetLastError();
            free(modules);
            CloseHandle(process);

            fprintf(stderr,
                    "[ERROR] EnumProcessModules failed: %lu\n",
                    error);
            return 1;
        }
    }

    DWORD count = needed / sizeof(HMODULE);

    printf("PID: %lu\n", (unsigned long)pid);
    printf("Loaded modules: %lu\n\n", (unsigned long)count);

    for (DWORD i = 0; i < count; i++) {
        char path[32768];

        DWORD length = GetModuleFileNameExA(
            process,
            modules[i],
            path,
            sizeof(path)
        );

        if (length == 0) {
            printf("[ERROR] Module path unavailable (error %lu)\n",
                   GetLastError());
            continue;
        }

        if (length >= sizeof(path)) {
            printf("[WARN] Module path may be truncated.\n");
        }

        printf("%s\n", path);
    }

    if (modules != initial_modules)
        free(modules);

    CloseHandle(process);
    return 0;
}


static int list_modules_by_name(const char *name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[ERROR] Snapshot failed: %lu\n", GetLastError());
        return 1;
    }
    PROCESSENTRY32 entry = {0};
    entry.dwSize = sizeof(entry);
    if (!Process32First(snapshot, &entry)) {
        DWORD error = GetLastError();
        CloseHandle(snapshot);
        fprintf(stderr, "[ERROR] Process32First failed: %lu\n", error);
        return 1;
    }
    int found = 0;
    do {
        if (!name_equal(entry.szExeFile, name))
            continue;
        if (found)
            printf("\n");
        found = 1;
        if (list_modules(entry.th32ProcessID) != 0)
            fprintf(stderr, "[WARN] Could not list modules for PID %lu.\n",
                    (unsigned long)entry.th32ProcessID);
    } while (Process32Next(snapshot, &entry));
    DWORD error = GetLastError();
    CloseHandle(snapshot);
    if (!found) {
        fprintf(stderr, "[INFO] No matching process found.\n");
        return 1;
    }
    if (error != ERROR_NO_MORE_FILES)
        fprintf(stderr, "[WARN] Enumeration ended unexpectedly: %lu\n", error);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "[ERROR] No command specified. Use -help for usage.\n");
        return 1;
    }
    if (strcmp(argv[1], "-help") == 0) {
        print_help();
        return 0;
    }
    if (strcmp(argv[1], "-processes") == 0) {
        if (argc != 2) {
            fprintf(stderr, "[ERROR] Usage: -processes\n");
            return 1;
        }
        return list_processes(NULL, 0);
    }
    if (strcmp(argv[1], "-pid") == 0) {
        if (argc != 3) {
            fprintf(stderr, "[ERROR] Usage: -pid <PID>\n");
            return 1;
        }
        char *end = NULL;
        unsigned long pid = strtoul(argv[2], &end, 10);
        if (argv[2][0] == '\0' || end == argv[2] || *end != '\0' || pid == 0 || pid > 0xFFFFFFFFUL) {
            fprintf(stderr, "[ERROR] Invalid PID: %s\n", argv[2]);
            return 1;
        }
        return list_processes(NULL, (DWORD)pid);
    }
    if (strcmp(argv[1], "-modules") == 0) {
        if (argc != 3) {
            fprintf(stderr, "[ERROR] Usage: -modules <PID>\n");
            return 1;
        }

        char *end = NULL;
        unsigned long pid = strtoul(argv[2], &end, 10);
        if (argv[2][0] == '\0' || end == argv[2] || *end != '\0' ||
            pid == 0 || pid > 0xFFFFFFFFUL) {
            fprintf(stderr, "[ERROR] Invalid PID: %s\n", argv[2]);
            return 1;
        }

        return list_modules((DWORD)pid);
    }
    if (strcmp(argv[1], "-modules-name") == 0) {
        if (argc != 3 || argv[2][0] == '\0') {
            fprintf(stderr, "[ERROR] Usage: -modules-name <PROCESS_NAME>\n");
            return 1;
        }
        return list_modules_by_name(argv[2]);
    }    if (strcmp(argv[1], "-name") == 0) {
        if (argc != 3 || argv[2][0] == '\0') {
            fprintf(stderr, "[ERROR] Usage: -name <PROCESS_NAME>\n");
            return 1;
        }
        return list_processes(argv[2], 0);
    }

    if (strcmp(argv[1], "-monitor-pid") == 0) {
    if (argc != 3) {
        fprintf(stderr,
                "[ERROR] Usage: -monitor-pid <PID>\n");
        return 1;
    }

    char *end = NULL;
    unsigned long pid = strtoul(argv[2], &end, 10);

    if (argv[2][0] == '\0' ||
        end == argv[2] ||
        *end != '\0' ||
        pid == 0 ||
        pid > 0xFFFFFFFFUL) {

        fprintf(stderr,
                "[ERROR] Invalid PID: %s\n",
                argv[2]);

        return 1;
    }

    if (!process_id_exists((DWORD)pid)) {
        fprintf(stderr, "[ERROR] PID %lu is not a running process.\n", pid);
        return 1;
    }

    return monitor_pid((DWORD)pid);
    }

    if (strcmp(argv[1], "-monitor-name") == 0) {
    if (argc != 3 || argv[2][0] == '\0') {
        fprintf(stderr,
                "[ERROR] Usage: -monitor-name <PROCESS_NAME>\n");
        return 1;
    }

    return monitor_name(argv[2]);
    }

    if (strcmp(argv[1], "-monitor-unload") == 0 ||
        strcmp(argv[1], "-monitor-name-not-found") == 0 ||
        strcmp(argv[1], "-monitor-resolution") == 0) {
        if (argc != 3 || argv[2][0] == '\0') {
            fprintf(stderr, "[ERROR] Usage: %s <PROCESS_NAME|PID>\n", argv[1]);
            return 1;
        }

        DLLWATCH_FILTER filter =
            strcmp(argv[1], "-monitor-unload") == 0
                ? DLLWATCH_FILTER_UNLOAD
                : strcmp(argv[1], "-monitor-name-not-found") == 0
                    ? DLLWATCH_FILTER_NOT_FOUND
                    : DLLWATCH_FILTER_RESOLUTION;

        char *end = NULL;
        unsigned long pid_value = strtoul(argv[2], &end, 10);
        int is_pid = end != argv[2] && *end == '\0';
        if (is_pid && (pid_value == 0 || pid_value > 0xFFFFFFFFUL)) {
            fprintf(stderr, "[ERROR] Invalid PID: %s\n", argv[2]);
            return 1;
        }

        if (is_pid) {
            if (!process_id_exists((DWORD)pid_value)) {
                fprintf(stderr, "[ERROR] PID %lu is not a running process.\n", pid_value);
                return 1;
            }
            return monitor_pid_filtered((DWORD)pid_value, filter);
        }

        return monitor_name_filtered(argv[2], filter);
    }

    if (strcmp(argv[1], "-monitor-lifecycle") == 0) {
        if (argc != 3 || argv[2][0] == '\0') {
            fprintf(stderr,
                    "[ERROR] Usage: -monitor-lifecycle <PROCESS_NAME|PID>\n");
            return 1;
        }

        char *end = NULL;
        unsigned long pid_value = strtoul(argv[2], &end, 10);
        int is_pid = end != argv[2] && *end == '\0';
        if (is_pid && (pid_value == 0 || pid_value > 0xFFFFFFFFUL)) {
            fprintf(stderr, "[ERROR] Invalid PID: %s\n", argv[2]);
            return 1;
        }
        if (is_pid) {
            if (!process_id_exists((DWORD)pid_value)) {
                fprintf(stderr, "[ERROR] PID %lu is not a running process.\n", pid_value);
                return 1;
            }
            return monitor_pid_filtered((DWORD)pid_value, DLLWATCH_FILTER_LIFECYCLE);
        }
        return monitor_name_filtered(argv[2], DLLWATCH_FILTER_LIFECYCLE);
    }

    fprintf(stderr, "[ERROR] Command not found: %s\n", argv[1]);
    fprintf(stderr, "Use -help to see available commands.\n");
    return 1;
}



