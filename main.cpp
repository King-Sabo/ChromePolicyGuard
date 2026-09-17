// ChromePolicyGuard - Windows service that removes Chrome/Chromium policy keys
// as soon as they appear, in HKLM and in every loaded user hive (HKU\<SID>).
//
// Design:
//  * Targets are deleted the moment they exist, so the only event that matters
//    is a target (or an ancestor) being CREATED. We therefore watch the parent
//    keys non-recursively for subkey name changes only; unrelated policy churn
//    under SOFTWARE\Policies\Microsoft etc. does not wake us.
//  * Every wake rebuilds the whole watch set (new event, new key handles), then
//    deletes. Arming before deleting closes the race window; our own delete
//    causes exactly one more (no-op) pass. Using a fresh event per generation
//    means signals from closing old handles can't cause a rebuild loop.
//  * The service runs as LocalSystem, whose HKCU is not the user's. User
//    policies live in HKU\<SID>, so each loaded user hive is watched.
//  * Open handles pin a hive. On logoff all user-hive handles are released so
//    the User Profile Service can unload the profile; user watches come back
//    after LOGOFF_RESCAN_DELAY_MS (or at the next logon).
//  * No heap allocations: fixed-size static tables.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>
#include <stdio.h>

#include "resource.h"

static const wchar_t kServiceName[] = L"ChromePolicyGuard";
static const wchar_t kServiceDesc[] = L"Remove organization enforced Chrome policy settings";

// Policy keys to remove, relative to HKLM or HKU\<SID>.
struct Target {
    const wchar_t* parent;
    const wchar_t* child;
};
static const Target kTargets[] = {
    { L"SOFTWARE\\Policies\\Google", L"Chrome"   },
    { L"SOFTWARE\\Policies",         L"Chromium" },
};

#define MAX_USER_HIVES          64
#define WATCHES_PER_HIVE        2                 // Policies (or SOFTWARE) + Policies\Google
#define MAX_WATCH_KEYS          (1 + (1 + MAX_USER_HIVES) * WATCHES_PER_HIVE)  // +1: HKU itself
#define SID_CCH                 256
#define PATH_CCH                512
#define LOGOFF_RESCAN_DELAY_MS  30000

struct WatchSet {
    HANDLE event;                                 // shared by all keys in this generation
    HKEY   keys[MAX_WATCH_KEYS];
    DWORD  count;
};

static SERVICE_STATUS        g_Status;
static SERVICE_STATUS_HANDLE g_StatusHandle;
static HANDLE                g_StopEvent;         // manual reset
static HANDLE                g_RescanEvent;       // auto reset: session logon
static HANDLE                g_LogoffEvent;       // auto reset: session logoff

static WatchSet g_WatchA, g_WatchB;
static wchar_t  g_Sids[MAX_USER_HIVES][SID_CCH];

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------

// HKLM: returns rel. HKU: returns "<sid>\<rel>" in buf (nullptr on overflow).
static const wchar_t* HivePath(const wchar_t* sid, const wchar_t* rel, wchar_t* buf, size_t cch)
{
    if (!sid) return rel;
    return SUCCEEDED(StringCchPrintfW(buf, cch, L"%s\\%s", sid, rel)) ? buf : nullptr;
}

static HKEY HiveRoot(const wchar_t* sid)
{
    return sid ? HKEY_USERS : HKEY_LOCAL_MACHINE;
}

static bool Arm(WatchSet& ws, HKEY root, const wchar_t* path)
{
    if (!path || ws.count >= MAX_WATCH_KEYS) return false;

    // SOFTWARE\Policies is a WOW64 shared key: one view covers both.
    HKEY hKey;
    if (RegOpenKeyExW(root, path, 0, KEY_NOTIFY | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return false;

    if (RegNotifyChangeKeyValue(hKey, FALSE, REG_NOTIFY_CHANGE_NAME, ws.event, TRUE) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    ws.keys[ws.count++] = hKey;
    return true;
}

static void ArmHive(WatchSet& ws, const wchar_t* sid)
{
    wchar_t buf[PATH_CCH];
    HKEY root = HiveRoot(sid);

    // Policies missing: watch SOFTWARE so its creation wakes us (next rebuild
    // then watches Policies).
    if (!Arm(ws, root, HivePath(sid, L"SOFTWARE\\Policies", buf, PATH_CCH)))
        Arm(ws, root, HivePath(sid, L"SOFTWARE", buf, PATH_CCH));

    // Chrome lives one level deeper; Google's creation is caught by the watch above.
    Arm(ws, root, HivePath(sid, L"SOFTWARE\\Policies\\Google", buf, PATH_CCH));
}

static void CleanHive(const wchar_t* sid)
{
    static const REGSAM kViews[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
    wchar_t buf[PATH_CCH];
    HKEY root = HiveRoot(sid);

    for (const Target& t : kTargets) {
        const wchar_t* parent = HivePath(sid, t.parent, buf, PATH_CCH);
        if (!parent) continue;

        for (REGSAM view : kViews) {
            HKEY hParent;
            if (RegOpenKeyExW(root, parent, 0, KEY_ALL_ACCESS | view, &hParent) == ERROR_SUCCESS) {
                RegDeleteTreeW(hParent, t.child);   // ERROR_FILE_NOT_FOUND is the normal case
                RegCloseKey(hParent);
            }
        }
    }
}

// Loaded user hives: HKU\S-1-5-21-* (local/AD) and HKU\S-1-12-1-* (Entra ID).
// Skips .DEFAULT, well-known service SIDs, and *_Classes.
static DWORD EnumUserHives()
{
    DWORD n = 0;
    for (DWORD i = 0; n < MAX_USER_HIVES; ++i) {
        DWORD cch = SID_CCH;
        LONG rc = RegEnumKeyExW(HKEY_USERS, i, g_Sids[n], &cch, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;

        const wchar_t* s = g_Sids[n];
        bool userSid = CompareStringOrdinal(s, 9, L"S-1-5-21-", 9, TRUE) == CSTR_EQUAL ||
                       CompareStringOrdinal(s, 9, L"S-1-12-1-", 9, TRUE) == CSTR_EQUAL;
        bool classes = cch > 8 &&
                       CompareStringOrdinal(s + cch - 8, 8, L"_Classes", 8, TRUE) == CSTR_EQUAL;
        if (userSid && !classes)
            ++n;
    }
    return n;
}

static void CloseWatchSet(WatchSet& ws)
{
    for (DWORD i = 0; i < ws.count; ++i)
        RegCloseKey(ws.keys[i]);
    ws.count = 0;
    if (ws.event) {
        CloseHandle(ws.event);
        ws.event = nullptr;
    }
}

// Arms a new generation, deletes targets, then drops the old generation.
// Returns the active set, or nullptr if no event could be created.
static WatchSet* Rebuild(WatchSet* current, bool includeUsers)
{
    WatchSet* next = (current == &g_WatchA) ? &g_WatchB : &g_WatchA;

    next->count = 0;
    next->event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!next->event)
        return current;                          // keep the old generation alive

    Arm(*next, HKEY_USERS, L"");                  // hive load/unload (best effort)
    ArmHive(*next, nullptr);

    DWORD users = includeUsers ? EnumUserHives() : 0;
    for (DWORD i = 0; i < users; ++i)
        ArmHive(*next, g_Sids[i]);

    CleanHive(nullptr);
    for (DWORD i = 0; i < users; ++i)
        CleanHive(g_Sids[i]);

    if (current)
        CloseWatchSet(*current);
    return next;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

static void ReportStatus(DWORD state, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkPoint = 1;

    g_Status.dwCurrentState  = state;
    g_Status.dwWin32ExitCode = exitCode;
    g_Status.dwWaitHint      = waitHint;
    g_Status.dwControlsAccepted = (state == SERVICE_START_PENDING || state == SERVICE_STOPPED)
        ? 0
        : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE;
    g_Status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;

    SetServiceStatus(g_StatusHandle, &g_Status);
}

static DWORD WINAPI ServiceCtrlHandlerEx(DWORD control, DWORD eventType, LPVOID, LPVOID)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        SetEvent(g_StopEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE:
        if (eventType == WTS_SESSION_LOGON)
            SetEvent(g_RescanEvent);
        else if (eventType == WTS_SESSION_LOGOFF)
            SetEvent(g_LogoffEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static DWORD RunWatcher()
{
    HANDLE timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    if (!timer)
        return GetLastError();

    bool usersSuspended = false;
    WatchSet* ws = Rebuild(nullptr, true);
    if (!ws) {
        CloseHandle(timer);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    DWORD result = NO_ERROR;
    for (;;) {
        HANDLE waits[] = { g_StopEvent, ws->event, g_RescanEvent, g_LogoffEvent, timer };
        DWORD w = WaitForMultipleObjects(ARRAYSIZE(waits), waits, FALSE, INFINITE);

        if (w == WAIT_OBJECT_0)                       // stop
            break;

        switch (w) {
        case WAIT_OBJECT_0 + 1:                       // registry change
        case WAIT_OBJECT_0 + 2:                       // logon
            ws = Rebuild(ws, !usersSuspended);
            break;

        case WAIT_OBJECT_0 + 3: {                     // logoff: release user hives
            LARGE_INTEGER due;
            due.QuadPart = -static_cast<LONGLONG>(LOGOFF_RESCAN_DELAY_MS) * 10000;
            usersSuspended = true;
            ws = Rebuild(ws, false);
            SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE);
            break;
        }

        case WAIT_OBJECT_0 + 4:                       // post-logoff delay elapsed
            usersSuspended = false;
            ws = Rebuild(ws, true);
            break;

        default:                                      // WAIT_FAILED: don't spin
            result = GetLastError();
            goto done;
        }
    }
done:
    CloseWatchSet(*ws);
    CloseHandle(timer);
    return result;
}

static VOID WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_StatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceCtrlHandlerEx, nullptr);
    if (!g_StatusHandle)
        return;

    g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_StopEvent   = CreateEventW(nullptr, TRUE,  FALSE, nullptr);
    g_RescanEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_LogoffEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    DWORD result = (g_StopEvent && g_RescanEvent && g_LogoffEvent) ? RunWatcher() : GetLastError();

    if (g_LogoffEvent) CloseHandle(g_LogoffEvent);
    if (g_RescanEvent) CloseHandle(g_RescanEvent);
    if (g_StopEvent)   CloseHandle(g_StopEvent);

    ReportStatus(SERVICE_STOPPED, result, 0);
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

static int Fail(const wchar_t* what)
{
    DWORD err = GetLastError();
    fwprintf(stderr, L"%s failed (%lu)%s\n", what, err,
             err == ERROR_ACCESS_DENIED ? L" - run from an elevated prompt" : L"");
    return 1;
}

static int Install()
{
    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return Fail(L"GetModuleFileName");

    // Quoted: an unquoted image path with spaces is a privilege-escalation vector.
    wchar_t cmd[MAX_PATH + 2];
    if (FAILED(StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%s\"", exe))) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return Fail(L"Building image path");
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm)
        return Fail(L"OpenSCManager");

    SC_HANDLE svc = CreateServiceW(scm, kServiceName, kServiceName,
        SERVICE_CHANGE_CONFIG | SERVICE_START, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd,
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        int rc = Fail(L"CreateService");
        CloseServiceHandle(scm);
        return rc;
    }

    SERVICE_DESCRIPTIONW sd = { const_cast<LPWSTR>(kServiceDesc) };
    if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &sd))
        Fail(L"ChangeServiceConfig2");                // non-fatal

    int rc = 0;
    if (!StartServiceW(svc, 0, nullptr))
        rc = Fail(L"StartService");
    else
        wprintf(L"Service installed and started.\n");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return rc;
}

static int Uninstall()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return Fail(L"OpenSCManager");

    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) {
        int rc = Fail(L"OpenService");
        CloseServiceHandle(scm);
        return rc;
    }

    SERVICE_STATUS st;
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        for (int i = 0; i < 50 && QueryServiceStatus(svc, &st) && st.dwCurrentState != SERVICE_STOPPED; ++i)
            Sleep(200);
    } else if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
        Fail(L"ControlService(STOP)");                // continue: still mark for deletion
    }

    int rc = 0;
    if (!DeleteService(svc))
        rc = Fail(L"DeleteService");
    else
        wprintf(L"Service uninstalled.\n");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return rc;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc > 1) {
        if (lstrcmpiW(argv[1], L"-install") == 0)   return Install();
        if (lstrcmpiW(argv[1], L"-uninstall") == 0) return Uninstall();
    }

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    if (StartServiceCtrlDispatcherW(table))
        return 0;

    if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        return Fail(L"StartServiceCtrlDispatcher");

    // Started from a console, not by the SCM.
    wprintf(L"ChromePolicyGuard " L"" CPG_VER_STR L"\n");
    wprintf(L"Usage: ChromePolicyGuard.exe [-install | -uninstall]   (elevated)\n");
    return argc > 1 ? 1 : 0;
}
