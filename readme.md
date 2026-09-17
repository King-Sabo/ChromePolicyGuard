# ChromePolicyGuard

[![build](https://github.com/King-Sabo/ChromePolicyGuard/actions/workflows/build.yml/badge.svg)](https://github.com/King-Sabo/ChromePolicyGuard/actions/workflows/build.yml)

A lightweight, zero-overhead Windows Service written in plain Win32 C++ that automatically monitors and deletes group policy registry keys for Google Chrome and Chromium  forced by the clue-less pencil pushers from the IT department (`Managed by your organization`).

## Features

* **Event-Driven Architecture:** Uses `RegNotifyChangeKeyValue` rather than polling, consuming 0% CPU while idling.
  Only the *parent* keys are watched, non-recursively and for subkey creation/deletion only, so unrelated
  policy churn (Windows, Defender, Office, ...) does not wake the service.
* **Race-free re-arming:** On every wake the watches are re-armed *before* anything is deleted, so a policy
  written in between is still caught.
* **All users, not just SYSTEM:** A service's `HKCU` is LocalSystem's own hive, not the logged-on user's.
  ChromePolicyGuard therefore watches every loaded user hive under `HKEY_USERS` and rescans on logon.
* **Profile-friendly:** On logoff all user-hive handles are released so the User Profile Service can unload
  the profile; user watches return 30 s later (or at the next logon).
* **WOW64:** `SOFTWARE\Policies` is a WOW64 shared key, so one watch covers both views; deletion is still
  issued against both the 64-bit and 32-bit views.
* **No heap allocations:** Fixed-size static tables (up to 64 loaded user hives).
* **Self-Installing:** Built-in command-line arguments to install and remove the Windows Service without external tools.
  The service image path is registered quoted.

## Target Keys Removed

* `HKLM\SOFTWARE\Policies\Google\Chrome`
* `HKLM\SOFTWARE\Policies\Chromium`
* `HKU\<SID>\SOFTWARE\Policies\Google\Chrome` (i.e. each user's `HKCU\...`)
* `HKU\<SID>\SOFTWARE\Policies\Chromium`

User hives are those of local/AD accounts (`S-1-5-21-*`) and Entra ID accounts (`S-1-12-1-*`).
Other Google policies (e.g. `SOFTWARE\Policies\Google\Update`) are left alone.

> **Limitation:** Chrome Browser Cloud Management (policies pushed from the Google Admin console and cached
> by Chrome itself) does not use these registry keys and is not affected.

## Command-Line Arguments

When executed from an **elevated** terminal, `ChromePolicyGuard.exe` supports the following options:

| Flag         | Description                                                                                                  |
|:------------ |:------------------------------------------------------------------------------------------------------------ |
| `-install`   | Registers `ChromePolicyGuard` as a Windows Service (Automatic startup) and immediately starts execution.     |
| `-uninstall` | Stops the running service (waits up to 10 s), then unregisters it from the Service Control Manager.       |

## Building

Both build paths compile `main.cpp` plus `ChromePolicyGuard.rc` (VERSIONINFO, version
numbers in `resource.h`) and link the CRT statically (`/MT`), so the EXE runs without
the VC++ redistributable.

### Option A: Visual Studio 2022 (v143 toolset)

1. Open `ChromePolicyGuard.sln` in Visual Studio.
2. Set build context to **Release | x64**.
3. Press `Ctrl + Shift + B` to compile.

Output: `x64\Release\ChromePolicyGuard.exe`

Or from a Developer Command Prompt:

```cmd
msbuild ChromePolicyGuard.sln /p:Configuration=Release /p:Platform=x64 /m
```

### Option B: CMake (3.15+)

```cmd
cmake -S . -B build -A x64
cmake --build build --config Release
```

Output: `build\Release\ChromePolicyGuard.exe`

## Versioning

Bump `CPG_VER_MAJOR` / `MINOR` / `PATCH` / `BUILD` in `resource.h`. The values end up in
the EXE's file properties (*Details* tab) and can be checked with:

```powershell
(Get-Item .\ChromePolicyGuard.exe).VersionInfo | Format-List FileVersion, ProductVersion
```

## Continuous integration

`.github/workflows/build.yml` runs on every push to `main`/`master`, on pull requests, and
manually (`workflow_dispatch`), on `windows-latest`:

| Job       | Builds                              | Matrix             |
|:--------- |:----------------------------------- |:------------------ |
| `msbuild` | `ChromePolicyGuard.sln` via MSBuild | x64 Debug, Release |
| `cmake`   | `CMakeLists.txt` (VS generator)     | x64 Debug, Release |

Each leg fails if `ChromePolicyGuard.exe` is missing or has no version resource, prints
the embedded version, and uploads the EXE as a workflow artifact
(`ChromePolicyGuard-<vs|cmake>-x64-<config>`, 7-day retention). These are **not releases**:
unsigned, expiring, and only downloadable with a GitHub login.
