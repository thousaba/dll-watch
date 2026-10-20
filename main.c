#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "Psapi.lib")
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void print_help(void)
{
    printf("dll-watch - Windows DLL monitoring tool\n\n");
    printf("Usage:\n");
    printf("  dll-watch.exe -help\n");
    printf("  dll-watch.exe -processes\n");
    printf("  dll-watch.exe -pid <PID>\n");
    printf("  dll-watch.exe -modules <PID>\n");
    printf("  dll-watch.exe -modules-name <PROCESS_NAME>\n");
    printf("  dll-watch.exe -name <PROCESS_NAME>\n");
}

static int name_equal(const char *a, const char *b)
{
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);

    if (len_a >= 4 && _stricmp(a + len_a - 4, ".exe") == 0)
        len_a -= 4;

    if (len_b >= 4 && _stricmp(b + len_b - 4, ".exe") == 0)
        len_b -= 4;

    return len_a == len_b && _strnicmp(a, b, len_a) == 0;
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

    fprintf(stderr, "[ERROR] Command not found: %s\n", argv[1]);
    fprintf(stderr, "Use -help to see available commands.\n");
    return 1;
}



