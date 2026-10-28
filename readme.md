# DLL Watch

DLL Watch is a Windows command-line tool written in C for inspecting processes, listing loaded modules, and monitoring successful DLL load events in real time through ETW.

## Features

- List running processes with PID, parent PID, executable name, and image path.
- Filter the process list by PID or executable name.
- Enumerate currently loaded module paths by PID or process name.
- Monitor DLL load events for a process by PID or process name.
- Display the event PID, process image path when available, DLL base address, image size, and DLL path.
- Classify DLL paths by location and report a separate writable-context hint.
- Match process names with or without the `.exe` suffix, without regard to letter case.
- Check that a PID exists before starting `-monitor-pid` monitoring.

Module enumeration is a snapshot of modules currently loaded. ETW monitoring reports new DLL load events after the monitoring session starts; it does not provide a retroactive list of modules already loaded.

The lifecycle monitor pairs DLL load and unload events by PID, image base, and path. It derives displayed event times from ETW timestamps and computes lifetime from their 100-nanosecond FILETIME intervals, marks unloads whose load event was not observed, and labels a process as tearing down when its PID is no longer present. It provides lifecycle context and does not make a suspiciousness verdict.

DLL path classification reports a semantic location (`system32`, `syswow64`, `winsxs`, `program-files`, `application-directory`, `appdata`, `temp`, `downloads`, `public`, or `other`) and a separate `Writable` hint. The hint is based on these standard locations, not a live ACL check; `unknown` means the tool cannot infer writability from the path alone. Neither field is a suspiciousness verdict.

## Requirements

- Windows 8 or later for a custom named system logger session that receives SystemTraceProvider events.
- A C compiler with Windows SDK or MinGW-w64 headers and libraries.
- Sufficient privileges to start a system logger session. Run from an elevated terminal if ETW reports an access error.

## Build

From the `src` directory, with Microsoft Visual C (Developer Command Prompt):

```bat
cl /W4 main.c etw_monitor.c dll_path.c dll_resolution.c dll_lifecycle.c /link Psapi.lib Advapi32.lib Tdh.lib
```

With MinGW-w64:

```bat
gcc -Wall -Wextra -Wpedantic -o dll-watch.exe main.c etw_monitor.c dll_path.c dll_resolution.c dll_lifecycle.c -lpsapi -ladvapi32 -ltdh
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
dll-watch.exe -monitor-unload <PROCESS_NAME|PID>
dll-watch.exe -monitor-lifecycle <PROCESS_NAME|PID>
dll-watch.exe -monitor-name-not-found <PROCESS_NAME|PID>
dll-watch.exe -monitor-resolution <PROCESS_NAME|PID>
```

Process names may be given with or without `.exe`. Name-based monitoring tracks every currently running process with that name and any matching process that starts while monitoring. PID-based monitoring targets only the specified process. `-monitor-name` reports DLL loads. `-monitor-name-not-found` reports missing `.dll` search candidates that end with `STATUS_OBJECT_NAME_NOT_FOUND`. `-monitor-resolution` keeps those individual lookup and load events, and also correlates matching PID and DLL basenames when a load follows a failed lookup within five seconds. This is a time-based correlation, not proof of loader causality. Monitoring continues until the program is stopped, for example with `Ctrl+C`.

Use `-monitor-unload` to show raw DLL unload events, `-monitor-lifecycle` to correlate loads and unloads, `-monitor-name-not-found` to show only `.dll` file open attempts that end with `STATUS_OBJECT_NAME_NOT_FOUND`, or `-monitor-resolution` to show lookup-to-load correlations. These commands accept a process name or PID.

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
dll-watch.exe -monitor-unload <PROCESS_NAME>
dll-watch.exe -monitor-unload 4520
dll-watch.exe -monitor-lifecycle <PROCESS_NAME>
dll-watch.exe -monitor-lifecycle 4520
dll-watch.exe -monitor-name-not-found <PROCESS_NAME>
dll-watch.exe -monitor-name-not-found 4520
dll-watch.exe -monitor-resolution <PROCESS_NAME>
dll-watch.exe -monitor-resolution 4520
```

A DLL load event is printed with the process PID and image path (or `<unavailable>`), DLL base address, image size, and DLL path. Lifecycle records show load and unload times, fractional-millisecond lifetime, process state, and whether the unload was normal or part of process teardown. Unmatched unloads are reported when the load happened before monitoring began. `NAME NOT FOUND` events include the target PID and attempted path. If a previous `DllWatchKernelSession` session remains, the tool attempts to stop that named session and start it again. It does not stop the NT Kernel Logger session.

## Roadmap

- [x] Capture file open attempts that end with `NAME NOT FOUND`.
- [x] Add separate monitoring commands for unloaded DLLs and not-found paths.
- [x] Classify DLL paths by semantic location and writable context.
- [ ] Check DLL signatures and expected signer information.
- [ ] Track repeated load/unload patterns and unusual process-to-DLL relationships.
- [x] Correlate DLL loads and unloads and report module lifetimes.
- [x] Correlate failed lookups with later loads by PID, DLL basename, and a five-second time window.
- [ ] Correlate loads with later process access and thread-creation activity.
- [ ] Handle processes that start or exit while monitoring.
- [ ] Add optional CSV output and analysis features for DLL search-order hijacking research.

## Notes

Windows may deny access to protected or elevated processes. The process image path may therefore be unavailable even when the ETW event is received. A custom system logger session can only be multiplexed with SystemTraceProvider on Windows 8 and later; Windows 7 and Windows Server 2008 R2 support that provider only through the NT Kernel Logger session.
