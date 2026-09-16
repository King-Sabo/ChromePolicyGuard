# ChromePolicyGuard

A lightweight, zero-overhead Windows Service written in pure C/Win32 that automatically monitors and deletes group policy registry keys for Google Chrome and Chromium  forced by the clue-less pencil pushers from the IT department (`Managed by your organization`).

## Features

* **Event-Driven Architecture:** Uses `RegNotifyChangeKeyValue` rather than polling, consuming 0% CPU while idling.
* **Pure Win32 Implementation:** Zero CRT heap allocations (`std::vector` free), using stack-allocated structures.
* **WOW64 Awareness:** Inspects and cleans up both native 64-bit and 32-bit registry hive views (`WOW6432Node`).
* **Self-Installing:** Built-in command-line arguments to install and remove the Windows Service without external tools.

## Target Keys Monitored

* `HKLM\SOFTWARE\Policies\Google\Chrome`
* `HKLM\SOFTWARE\Policies\Chromium`
* `HKCU\SOFTWARE\Policies\Google\Chrome`
* `HKCU\SOFTWARE\Policies\Chromium`

## Command-Line Arguments

When executed interactively from a terminal, `ChromePolicyGuard.exe` supports the following options:

| Flag         | Description                                                                                                  |
|:------------ |:------------------------------------------------------------------------------------------------------------ |
| `-install`   | Registers `ChromePolicyGuard` as a Windows Service (Automatic startup) and immediately starts execution.     |
| `-uninstall` | Signals the running service to stop, unregisters it from the Service Control Manager, and cleans up entries. |

## Building

### Option A: Visual Studio (2017, 2019, 2022)

1. Open `ChromePolicyGuard.vcxproj` in Visual Studio.
2. Set build context to **Release | x64**.
3. Press `Ctrl + Shift + B` to compile.

### Option B: CMake

```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release