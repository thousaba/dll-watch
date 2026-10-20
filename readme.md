# DLL Watch

DLL Watch is a Windows command-line tool written in C for inspecting processes and investigating DLL load behavior. The current version provides a process snapshot and can enumerate the modules currently loaded by a process. Real-time DLL load and failed-search monitoring are planned roadmap items.

## Current Features

- List running processes with PID, parent PID, executable name, and image path.
- Filter the process list by PID or executable name.
- Enumerate currently loaded module paths by PID or process name.
- Match process names with or without the `.exe` suffix, without regard to letter case.

> Module enumeration is a snapshot of modules currently loaded. It does not monitor new load or unload events in real time.

## Requirements

- Windows
- A C compiler with Windows SDK headers and libraries

## Build

With Microsoft Visual C (Developer Command Prompt):

```bat
cl /W4 main.c /link Psapi.lib
```

With MinGW-w64:

```bat
gcc -Wall -Wextra -o dll-watch.exe main.c -lpsapi
```

The source includes the Psapi header and requests `Psapi.lib` when built with MSVC. MinGW builds must link `psapi` explicitly.

## Usage

```text
dll-watch.exe -help
dll-watch.exe -processes
dll-watch.exe -pid <PID>
dll-watch.exe -name <PROCESS_NAME>
dll-watch.exe -modules <PID>
dll-watch.exe -modules-name <PROCESS_NAME>
```

### Examples

List all running processes:

```bat
dll-watch.exe -processes
```

Show a process by PID:

```bat
dll-watch.exe -pid 4520
```

Find processes by name (`.exe` is optional):

```bat
dll-watch.exe -name Spotify
```

List modules currently loaded by a process:

```bat
dll-watch.exe -modules 4520
```

List modules for every running process with the given name:

```bat
dll-watch.exe -modules-name Spotify.exe
```

## Roadmap

### 01. Process inventory and basic CLI

- [x] List running processes using `CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next`.
- [x] Show each process's PID and name in a readable table. The current table also includes PPID and image path.
- [x] Filter by a specific PID or process name.
- [x] Provide a readable table format.

### 02. Monitor successful DLL loads in real time

- [ ] Listen for ETW Image Load events.
- [ ] Display PID, process name, DLL path, and timestamp.
- [ ] Add the `-loaded` filter.

The goal is to capture new module load events as they happen, rather than relying only on a snapshot of a process's current module inventory.

### 03. Capture failed DLL searches

- [ ] Inspect file I/O telemetry.
- [ ] Identify `NAME NOT FOUND` results.
- [ ] Exclude file access events unrelated to DLL search behavior.
- [ ] Add the `-notfound` filter.

This stage requires careful event classification because a failed file access does not necessarily represent a failed DLL search.

### 04. Filtering and event correlation

- [ ] Support combined filters such as `-pid 4520`, `-process test.exe`, `-loaded`, `-notfound`, `-unloaded`, and `-dll version.dll`.
- [ ] Correlate relevant failed searches with successful loads using timing and path context.
- [ ] Present events in a unified output format.

### 05. Reliability and detection-oriented features

- [ ] Handle processes that start or exit while monitoring.
- [ ] Handle permission limitations and process architecture mismatches clearly.
- [ ] Filter noisy system DLL searches.
- [ ] Add optional CSV output.
- [ ] Add analysis features for DLL search-order hijacking research.

## Notes

Windows may deny access to protected or elevated processes. Module enumeration can also be affected when the target and utility have different 32-bit or 64-bit architectures. Real-time event monitoring and the roadmap filters are not implemented yet.
