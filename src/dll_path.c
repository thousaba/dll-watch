#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include "dll_path.h"

static void print_wide_utf8_raw(const WCHAR *value)
{
    if (value == NULL)
        return;
    int bytes_needed = WideCharToMultiByte(CP_UTF8, 0, value, -1,
                                           NULL, 0, NULL, NULL);
    if (bytes_needed <= 0)
        return;
    char *utf8 = malloc((size_t)bytes_needed);
    if (utf8 == NULL)
        return;
    if (WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8,
                            bytes_needed, NULL, NULL) > 0)
        fputs(utf8, stdout);
    free(utf8);
}

void dll_path_print(const WCHAR *value)
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
            QueryDosDeviceW(drive_name, drive_targets[letter - L'A'], MAX_PATH);
        }
        drive_targets_initialized = 1;
    }

    if (wcsncmp(value, L"\\Device\\", 8) == 0) {
        for (WCHAR letter = L'A'; letter <= L'Z'; letter++) {
            const WCHAR *device_target = drive_targets[letter - L'A'];
            size_t prefix_length = wcslen(device_target);
            if (prefix_length == 0 ||
                _wcsnicmp(value, device_target, prefix_length) != 0 ||
                (value[prefix_length] != L'\\' && value[prefix_length] != L'\0'))
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

void dll_path_print_classification(DWORD pid, const WCHAR *path)
{
    DLL_PATH_CLASSIFICATION classification = classify_dll_path(pid, path);
    printf("Location: ");
    dll_path_print(classification.location);
    printf("\nWritable: ");
    dll_path_print(classification.writable);
    printf("\n");
}

static int path_is_under(const WCHAR *path, const WCHAR *directory)
{
    size_t length;
    if (path == NULL || directory == NULL || directory[0] == L'\0')
        return 0;
    length = wcslen(directory);
    while (length > 0 && (directory[length - 1] == L'\\' || directory[length - 1] == L'/'))
        length--;
    return _wcsnicmp(path, directory, length) == 0 &&
        (path[length] == L'\0' || path[length] == L'\\' || path[length] == L'/');
}

DLL_PATH_CLASSIFICATION classify_dll_path(DWORD pid, const WCHAR *dll_path)
{
    WCHAR windows_dir[MAX_PATH];
    WCHAR system_dir[MAX_PATH];
    WCHAR process_path[MAX_PATH];
    WCHAR app_dir[MAX_PATH];
    WCHAR user_profile[MAX_PATH];
    WCHAR temp_dir[MAX_PATH];
    WCHAR public_dir[MAX_PATH];
    WCHAR downloads_dir[MAX_PATH];
    WCHAR program_files[MAX_PATH];
    WCHAR program_files_x86[MAX_PATH];
    WCHAR program_w6432[MAX_PATH];
    WCHAR subdir[MAX_PATH];
    WCHAR normalized_path[32768];
    WCHAR device_target[MAX_PATH];
    WCHAR drive_name[] = L"A:";
    const WCHAR *candidate = dll_path;
    WCHAR *last_separator;
    DWORD length;
    DWORD chars;
    int have_user_profile = 0;
    DLL_PATH_CLASSIFICATION result = { L"other", L"unknown" };

    if (dll_path != NULL && wcsncmp(dll_path, L"\\Device\\", 8) == 0) {
        DWORD drives = GetLogicalDrives();
        for (WCHAR drive = L'A'; drive <= L'Z'; drive++) {
            size_t prefix_length;
            drive_name[0] = drive;
            if ((drives & (1UL << (drive - L'A'))) == 0 ||
                QueryDosDeviceW(drive_name, device_target, MAX_PATH) == 0)
                continue;
            prefix_length = wcslen(device_target);
            if (prefix_length == 0 ||
                _wcsnicmp(dll_path, device_target, prefix_length) != 0 ||
                (dll_path[prefix_length] != L'\\' && dll_path[prefix_length] != L'\0'))
                continue;
            if (prefix_length + wcslen(dll_path + prefix_length) + 3 <
                sizeof(normalized_path) / sizeof(normalized_path[0])) {
                normalized_path[0] = drive;
                normalized_path[1] = L':';
                wcscpy(normalized_path + 2, dll_path + prefix_length);
                candidate = normalized_path;
            }
            break;
        }
    }

    length = GetWindowsDirectoryW(windows_dir, MAX_PATH);
    if (length > 0 && length < MAX_PATH) {
        wcscpy(subdir, windows_dir);
        wcscat(subdir, L"\\SysWOW64");
        if (path_is_under(candidate, subdir)) {
            result.location = L"syswow64";
            result.writable = L"no";
        } else {
            length = GetSystemDirectoryW(system_dir, MAX_PATH);
            if (length > 0 && length < MAX_PATH && path_is_under(candidate, system_dir)) {
                last_separator = wcsrchr(system_dir, L'\\');
                result.location = last_separator != NULL &&
                    _wcsicmp(last_separator + 1, L"SysWOW64") == 0
                    ? L"syswow64" : L"system32";
                result.writable = L"no";
            } else {
                wcscpy(subdir, windows_dir);
                wcscat(subdir, L"\\WinSxS");
                if (path_is_under(candidate, subdir)) {
                    result.location = L"winsxs";
                    result.writable = L"no";
                }
            }
        }
    }

    /* Application directory takes precedence over its broader parent category. */
    if (_wcsicmp(result.location, L"other") == 0) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        DWORD path_chars = MAX_PATH;
        if (process != NULL && QueryFullProcessImageNameW(process, 0, process_path, &path_chars)) {
            last_separator = wcsrchr(process_path, L'\\');
            if (last_separator == NULL)
                last_separator = wcsrchr(process_path, L'/');
            if (last_separator != NULL) {
                *last_separator = L'\0';
                wcscpy(app_dir, process_path);
                if (path_is_under(candidate, app_dir))
                    result.location = L"application-directory";
            }
        }
        if (process != NULL)
            CloseHandle(process);
    }

    if (_wcsicmp(result.location, L"other") == 0) {
        chars = GetEnvironmentVariableW(L"ProgramFiles", program_files, MAX_PATH);
        if (chars > 0 && chars < MAX_PATH && path_is_under(candidate, program_files)) {
            result.location = L"program-files";
            result.writable = L"no";
        }
        chars = GetEnvironmentVariableW(L"ProgramFiles(x86)", program_files_x86, MAX_PATH);
        if (chars > 0 && chars < MAX_PATH && path_is_under(candidate, program_files_x86)) {
            result.location = L"program-files";
            result.writable = L"no";
        }
        chars = GetEnvironmentVariableW(L"ProgramW6432", program_w6432, MAX_PATH);
        if (chars > 0 && chars < MAX_PATH && path_is_under(candidate, program_w6432)) {
            result.location = L"program-files";
            result.writable = L"no";
        }
    }

    chars = GetTempPathW(MAX_PATH, temp_dir);
    if (_wcsicmp(result.location, L"other") == 0 &&
        chars > 0 && chars < MAX_PATH && path_is_under(candidate, temp_dir)) {
        result.location = L"temp";
        result.writable = L"yes";
    }

    chars = GetEnvironmentVariableW(L"USERPROFILE", user_profile, MAX_PATH);
    have_user_profile = chars > 0 && chars < MAX_PATH;
    if (_wcsicmp(result.location, L"other") == 0 && have_user_profile) {
        wcscpy(subdir, user_profile);
        wcscat(subdir, L"\\AppData");
        if (path_is_under(candidate, subdir)) {
            result.location = L"appdata";
            result.writable = L"yes";
        } else {
            wcscpy(downloads_dir, user_profile);
            wcscat(downloads_dir, L"\\Downloads");
            if (path_is_under(candidate, downloads_dir)) {
                result.location = L"downloads";
                result.writable = L"yes";
            }
        }
    }

    if (_wcsicmp(result.location, L"other") == 0) {
        chars = GetEnvironmentVariableW(L"PUBLIC", public_dir, MAX_PATH);
        if (chars > 0 && chars < MAX_PATH && path_is_under(candidate, public_dir)) {
            result.location = L"public";
            result.writable = L"yes";
        }
    }
    if (_wcsicmp(result.location, L"application-directory") == 0) {
        result.writable = have_user_profile && path_is_under(candidate, user_profile)
            ? L"yes" : L"unknown";
    }

    return result;
}
