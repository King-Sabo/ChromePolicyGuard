#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>

#define SERVICE_NAME _T("ChromePolicyGuard")
#define SERVICE_DESC _T("Remove organization enforced Chrome policy settings")

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = NULL;

// Update target policy structure to track access flags
struct TargetPolicy {
    HKEY           hRootKey;
    const wchar_t* subKeyPath;
    const wchar_t* targetDelete;
    REGSAM         samDesired;
};

static const TargetPolicy g_Targets[] = {
    // 64-bit Registry Views
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Google", L"Chrome", KEY_NOTIFY | KEY_ALL_ACCESS | KEY_WOW64_64KEY },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies",        L"Chromium", KEY_NOTIFY | KEY_ALL_ACCESS | KEY_WOW64_64KEY },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Policies\\Google", L"Chrome", KEY_NOTIFY | KEY_ALL_ACCESS | KEY_WOW64_64KEY },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Policies",        L"Chromium", KEY_NOTIFY | KEY_ALL_ACCESS | KEY_WOW64_64KEY },

    // 32-bit Registry Views (WOW6432Node)
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Google", L"Chrome", KEY_NOTIFY | KEY_ALL_ACCESS | KEY_WOW64_32KEY },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies",        L"Chromium", KEY_NOTIFY | KEY_ALL_ACCESS | KEY_WOW64_32KEY },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Policies\\Google", L"Chrome", KEY_NOTIFY | KEY_ALL_ACCESS | KEY_WOW64_32KEY },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Policies",        L"Chromium", KEY_NOTIFY | KEY_ALL_ACCESS | KEY_WOW64_32KEY }
};

static const DWORD g_TargetCount = sizeof(g_Targets) / sizeof(g_Targets[0]);

void DeletePolicySubkey(HKEY hRoot, const wchar_t* parentPath, const wchar_t* childName) {
    HKEY hParent = NULL;
    if (RegOpenKeyExW(hRoot, parentPath, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hParent) == ERROR_SUCCESS) {
        RegDeleteTreeW(hParent, childName);
        RegCloseKey(hParent);
    }
    if (RegOpenKeyExW(hRoot, parentPath, 0, KEY_ALL_ACCESS | KEY_WOW64_32KEY, &hParent) == ERROR_SUCCESS) {
        RegDeleteTreeW(hParent, childName);
        RegCloseKey(hParent);
    }
}

DWORD WINAPI PolicyWatcherThread(LPVOID lpParam) {
    for (DWORD i = 0; i < g_TargetCount; ++i) {
        DeletePolicySubkey(g_Targets[i].hRootKey, g_Targets[i].subKeyPath, g_Targets[i].targetDelete);
    }

    HKEY   openKeys[g_TargetCount] = { NULL };
    HANDLE eventHandles[g_TargetCount + 1] = { NULL };
    DWORD  activeHandleCount = 0;

    eventHandles[activeHandleCount++] = g_ServiceStopEvent;

    for (DWORD i = 0; i < g_TargetCount; ++i) {
        HKEY hKey = NULL;
        LONG res = RegCreateKeyExW(g_Targets[i].hRootKey, g_Targets[i].subKeyPath, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_NOTIFY | KEY_ALL_ACCESS,
            NULL, &hKey, NULL);

        if (res == ERROR_SUCCESS) {
            HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
            if (hEvent) {
                RegNotifyChangeKeyValue(hKey, TRUE,
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                    hEvent, TRUE);

                openKeys[i] = hKey;
                eventHandles[activeHandleCount++] = hEvent;
            } else {
                RegCloseKey(hKey);
            }
        }
    }

    while (TRUE) {
        DWORD waitRes = WaitForMultipleObjects(
            activeHandleCount,
            eventHandles,
            FALSE,
            INFINITE
        );

        if (waitRes == WAIT_OBJECT_0) {
            break;
        }

        if (waitRes > WAIT_OBJECT_0 && waitRes < (WAIT_OBJECT_0 + activeHandleCount)) {
            DWORD triggerIdx = waitRes - WAIT_OBJECT_0 - 1;

            for (DWORD i = 0; i < g_TargetCount; ++i) {
                DeletePolicySubkey(g_Targets[i].hRootKey, g_Targets[i].subKeyPath, g_Targets[i].targetDelete);
            }

            RegNotifyChangeKeyValue(openKeys[triggerIdx], TRUE,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                eventHandles[triggerIdx + 1], TRUE);
        }
    }

    for (DWORD i = 0; i < g_TargetCount; ++i) {
        if (openKeys[i]) RegCloseKey(openKeys[i]);
    }
    for (DWORD i = 1; i < activeHandleCount; ++i) {
        if (eventHandles[i]) CloseHandle(eventHandles[i]);
    }

    return 0;
}

VOID WINAPI ServiceCtrlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        SetEvent(g_ServiceStopEvent);
        break;
    default:
        break;
    }
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_ServiceStopEvent) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    HANDLE hThread = CreateThread(NULL, 0, PolicyWatcherThread, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    CloseHandle(g_ServiceStopEvent);
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int _tmain(int argc, _TCHAR* argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        if (argc > 1) {
            if (_tcscmp(argv[1], _T("-install")) == 0) {
                TCHAR path[MAX_PATH];
                GetModuleFileName(NULL, path, MAX_PATH);
                SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
                if (scm) {
                    SC_HANDLE svc = CreateService(scm, SERVICE_NAME, SERVICE_NAME,
                        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                        path, NULL, NULL, NULL, NULL, NULL);
                    if (svc) {
                        SERVICE_DESCRIPTION sd;
                        sd.lpDescription = (LPTSTR)SERVICE_DESC;

                        BOOL bResult = ChangeServiceConfig2(
                            svc,
                            SERVICE_CONFIG_DESCRIPTION, // Info level flag
                            &sd                          // Pointer to SERVICE_DESCRIPTION
                        );

                        if (!bResult) {
                            _tprintf(_T("ChangeServiceConfig2 failed (%d)\n"), GetLastError());
                        }

                        StartService(svc, 0, NULL);
                        CloseHandle(svc);
                        _tprintf(_T("Service installed and started successfully.\n"));
                    }
                    CloseHandle(scm);
                }
                return 0;
            }
            if (_tcscmp(argv[1], _T("-uninstall")) == 0) {
                SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
                if (scm) {
                    SC_HANDLE svc = OpenService(scm, SERVICE_NAME, DELETE | SERVICE_STOP);
                    if (svc) {
                        SERVICE_STATUS status;
                        ControlService(svc, SERVICE_CONTROL_STOP, &status);
                        DeleteService(svc);
                        CloseHandle(svc);
                        _tprintf(_T("Service uninstalled successfully.\n"));
                    }
                    CloseHandle(scm);
                }
                return 0;
            }
        }
        _tprintf(_T("Chrome Policy Guard Service\n"));
        _tprintf(_T("Usage: ChromePolicyGuard.exe [-install | -uninstall]\n"));
    }
    return 0;
}
