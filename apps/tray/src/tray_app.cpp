#if defined(_WIN32)

#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>

#include <chrono>
#include <optional>
#include <string>

namespace {
constexpr wchar_t kWindowClassName[] = L"CertCtrlTrayWindow";
constexpr wchar_t kTrayTooltip[] = L"cert-ctrl agent";
constexpr wchar_t kServiceName[] = L"CertCtrlAgent";

constexpr UINT WMAPP_TRAYICON = WM_APP + 1;
constexpr UINT ID_TRAY_START = 1001;
constexpr UINT ID_TRAY_STOP = 1002;
constexpr UINT ID_TRAY_REFRESH = 1003;
constexpr UINT ID_TRAY_EXIT = 1004;

NOTIFYICONDATAW g_trayIconData{};
HINSTANCE g_instance = nullptr;

enum class ServiceState {
    Unknown,
    Stopped,
    Running,
    Pending
};

std::wstring ServiceStateToText(ServiceState state) {
    switch (state) {
    case ServiceState::Running:
        return L"Running";
    case ServiceState::Stopped:
        return L"Stopped";
    case ServiceState::Pending:
        return L"Pending";
    default:
        return L"Unknown";
    }
}

HICON IconForServiceState(ServiceState state) {
    switch (state) {
    case ServiceState::Running:
        return static_cast<HICON>(LoadImageW(nullptr, IDI_APPLICATION, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED));
    case ServiceState::Pending:
        return static_cast<HICON>(LoadImageW(nullptr, IDI_WARNING, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED));
    case ServiceState::Stopped:
    default:
        return static_cast<HICON>(LoadImageW(nullptr, IDI_ERROR, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED));
    }
}

std::optional<ServiceState> QueryServiceState() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return std::nullopt;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return std::nullopt;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    const bool ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (!ok) {
        return std::nullopt;
    }

    switch (status.dwCurrentState) {
    case SERVICE_RUNNING:
        return ServiceState::Running;
    case SERVICE_STOPPED:
        return ServiceState::Stopped;
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_PAUSE_PENDING:
        return ServiceState::Pending;
    default:
        return ServiceState::Unknown;
    }
}

bool StartCertCtrlService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    const bool startResult = StartServiceW(service, 0, nullptr) != 0;
    if (!startResult) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    auto startTime = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(15);
    bool running = false;
    while (std::chrono::steady_clock::now() - startTime < timeout) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
            break;
        }
        if (status.dwCurrentState == SERVICE_RUNNING) {
            running = true;
            break;
        }
        Sleep(300);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return running;
}

bool StopCertCtrlService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status{};
    const bool controlResult = ControlService(service, SERVICE_CONTROL_STOP, &status) != 0;
    if (!controlResult) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS procStatus{};
    DWORD bytesNeeded = 0;
    auto startTime = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(15);
    bool stopped = false;
    while (std::chrono::steady_clock::now() - startTime < timeout) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&procStatus), sizeof(procStatus), &bytesNeeded)) {
            break;
        }
        if (procStatus.dwCurrentState == SERVICE_STOPPED) {
            stopped = true;
            break;
        }
        Sleep(300);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return stopped;
}

void ShowMessage(HWND hwnd, const std::wstring &title, const std::wstring &body, UINT icon = MB_ICONINFORMATION) {
    MessageBoxW(hwnd, body.c_str(), title.c_str(), MB_OK | icon | MB_SETFOREGROUND);
}

void UpdateTrayIcon(ServiceState state) {
    g_trayIconData.hIcon = IconForServiceState(state);
    std::wstring status = L"cert-ctrl: " + ServiceStateToText(state);
    StringCchCopyW(g_trayIconData.szTip, ARRAYSIZE(g_trayIconData.szTip), status.c_str());
    Shell_NotifyIconW(NIM_MODIFY, &g_trayIconData);
}

void RefreshStateAndIcon(HWND hwnd) {
    auto stateOpt = QueryServiceState();
    if (!stateOpt) {
        UpdateTrayIcon(ServiceState::Unknown);
        ShowMessage(hwnd, L"Cert Ctrl", L"Unable to query service state.", MB_ICONWARNING);
        return;
    }
    UpdateTrayIcon(*stateOpt);
}

void ShowTrayMenu(HWND hwnd) {
    HMENU menu = CreatePopupMenu();
    if (!menu) {
        return;
    }

    auto state = QueryServiceState().value_or(ServiceState::Unknown);

    UINT startFlags = MF_STRING;
    UINT stopFlags = MF_STRING;
    if (state == ServiceState::Running) {
        startFlags |= MF_GRAYED;
    } else if (state == ServiceState::Stopped) {
        stopFlags |= MF_GRAYED;
    }

    AppendMenuW(menu, startFlags, ID_TRAY_START, L"Start service");
    AppendMenuW(menu, stopFlags, ID_TRAY_STOP, L"Stop service");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_REFRESH, L"Refresh status");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"Exit");

    POINT cursorPos{};
    GetCursorPos(&cursorPos);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_BOTTOMALIGN | TPM_LEFTBUTTON | TPM_RIGHTBUTTON, cursorPos.x, cursorPos.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        g_trayIconData = {};
        g_trayIconData.cbSize = sizeof(NOTIFYICONDATAW);
        g_trayIconData.hWnd = hwnd;
        g_trayIconData.uID = 1;
        g_trayIconData.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        g_trayIconData.uCallbackMessage = WMAPP_TRAYICON;
        g_trayIconData.hIcon = IconForServiceState(ServiceState::Unknown);
        StringCchCopyW(g_trayIconData.szTip, ARRAYSIZE(g_trayIconData.szTip), kTrayTooltip);
        Shell_NotifyIconW(NIM_ADD, &g_trayIconData);
        Shell_NotifyIconW(NIM_SETVERSION, &g_trayIconData);
        RefreshStateAndIcon(hwnd);
        return 0;

    case WM_APP:
        return DefWindowProcW(hwnd, message, wParam, lParam);

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_TRAY_START: {
            if (StartCertCtrlService()) {
                RefreshStateAndIcon(hwnd);
            } else {
                ShowMessage(hwnd, L"Cert Ctrl", L"Failed to start service.", MB_ICONERROR);
                RefreshStateAndIcon(hwnd);
            }
            return 0;
        }
        case ID_TRAY_STOP: {
            if (StopCertCtrlService()) {
                RefreshStateAndIcon(hwnd);
            } else {
                ShowMessage(hwnd, L"Cert Ctrl", L"Failed to stop service.", MB_ICONERROR);
                RefreshStateAndIcon(hwnd);
            }
            return 0;
        }
        case ID_TRAY_REFRESH:
            RefreshStateAndIcon(hwnd);
            return 0;
        case ID_TRAY_EXIT:
            DestroyWindow(hwnd);
            return 0;
        default:
            break;
        }
        break;
    }
    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_trayIconData);
        PostQuitMessage(0);
        return 0;

    case WMAPP_TRAYICON:
        switch (LOWORD(lParam)) {
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowTrayMenu(hwnd);
            return 0;
        case WM_LBUTTONDBLCLK:
            RefreshStateAndIcon(hwnd);
            return 0;
        default:
            break;
        }
        break;
    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    WNDCLASSEXW wcex{};
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = TrayWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = nullptr;
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wcex.lpszMenuName = nullptr;
    wcex.lpszClassName = kWindowClassName;
    wcex.hIconSm = nullptr;

    if (!RegisterClassExW(&wcex)) {
        return FALSE;
    }

    HWND hwnd = CreateWindowExW(0, kWindowClassName, kTrayTooltip, WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) {
        return FALSE;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    ShowWindow(hwnd, SW_HIDE);

    return TRUE;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                      _In_opt_ HINSTANCE /*hPrevInstance*/,
                      _In_ LPWSTR /*lpCmdLine*/,
                      _In_ int nCmdShow) {
    g_instance = hInstance;
    if (!InitInstance(hInstance, nCmdShow)) {
        return 1;
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

} // namespace

#else

int main() {
    return 0;
}

#endif  // defined(_WIN32)
