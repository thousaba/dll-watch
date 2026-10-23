# DLL Watch

DLL Watch is a Windows command-line tool written in C for inspecting processes, listing loaded modules, and monitoring successful DLL load events in real time through ETW.

## Features

- List running processes with PID, parent PID, executable name, and image path.
- Filter the process list by PID or executable name.
- Enumerate currently loaded module paths by PID or process name.
- Monitor DLL load events for a process by PID or process name.
- Display the event PID, process image path when available, DLL base address, image size, and DLL path.
- Match process names with or without the `.exe` suffix, without regard to letter case.
- Check that a PID exists before starting `-monitor-pid` monitoring.

Module enumeration is a snapshot of modules currently loaded. ETW monitoring reports new DLL load events after the monitoring session starts; it does not provide a retroactive list of modules already loaded.

Failed DLL searches, unload events, and DLL search-order hijacking analysis are not currently implemented.

## Requirements

- Windows 8 or later for a custom named system logger session that receives SystemTraceProvider events.
- A C compiler with Windows SDK or MinGW-w64 headers and libraries.
- Sufficient privileges to start a system logger session. Run from an elevated terminal if ETW reports an access error.

## Build

From the `src` directory, with Microsoft Visual C (Developer Command Prompt):

```bat
cl /W4 main.c etw_monitor.c /link Psapi.lib Advapi32.lib Tdh.lib
```

With MinGW-w64:

```bat
gcc -Wall -Wextra -Wpedantic -o dll-watch.exe main.c etw_monitor.c -lpsapi -ladvapi32 -ltdh
```

## Usage

```text
dll-watch.exe -help
dll-watch.exe -processes
dll-watch.exe -pid <PID>
dll-watch.exe -name <PROCESS_NAME>
dll-watch.exe -modules <PID>
dll-watch.exe -modules-name <PROCESS_NAME>
dll-watch.exe -monitor-pid <PID>
dll-watch.exe -monitor-name <PROCESS_NAME>
```

Process names may be given with or without `.exe`. `-monitor-name` selects the first matching running process. Monitoring continues until the program is stopped, for example with `Ctrl+C`.

### Examples

List all running processes:

```bat
dll-watch.exe -processes
```

Show a process by PID:

```bat
dll-watch.exe -pid 4520
```

Find processes by name:

```bat
dll-watch.exe -name <PROCESS_NAME>
```

List modules currently loaded by a process:

```bat
dll-watch.exe -modules 4520
dll-watch.exe -modules-name <PROCESS_NAME>
```

Monitor new DLL loads by PID or process name:

```bat
dll-watch.exe -monitor-pid 4520
dll-watch.exe -monitor-name <PROCESS_NAME>
```

A DLL load event is printed with the process PID and image path (or `<unavailable>`), DLL base address, image size, and DLL path. If a previous `DllWatchKernelSession` session remains, the tool attempts to stop that named session and start it again. It does not stop the NT Kernel Logger session.

## Roadmap

- [ ] Capture failed DLL searches by inspecting file I/O telemetry and identifying relevant `NAME NOT FOUND` results.
- [ ] Add event filters for loaded, unloaded, and not-found DLLs.
- [ ] Correlate failed searches with successful loads using timing and path context.
- [ ] Handle processes that start or exit while monitoring.
- [ ] Add optional CSV output and analysis features for DLL search-order hijacking research.

## Notes

Windows may deny access to protected or elevated processes. The process image path may therefore be unavailable even when the ETW event is received. A custom system logger session can only be multiplexed with SystemTraceProvider on Windows 8 and later; Windows 7 and Windows Server 2008 R2 support that provider only through the NT Kernel Logger session.
