#ifdef _WIN32

#include "cert_ctrl_entry.hpp"

#include <windows.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

// Forward declaration defined in cert_ctrl_entrypoint.cpp
extern int RunCertCtrlApplication(int argc, char *argv[]);

namespace {

wchar_t kServiceName[] = L"CertCtrlAgent";

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_service_status;
HANDLE g_worker_thread = nullptr;
std::atomic<bool> g_stop_requested{false};
std::vector<std::string> g_service_args;
std::vector<char *> g_service_arg_ptrs;

std::string WideToUtf8(const wchar_t *value) {
  if (!value) {
    return {};
  }
  int size = ::WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
  if (size <= 0) {
    return {};
  }
  std::string result(static_cast<size_t>(size - 1), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), size, nullptr, nullptr);
  return result;
}

void BuildServiceArguments(DWORD argc, LPWSTR *argv) {
  g_service_args.clear();
  g_service_arg_ptrs.clear();

  wchar_t module_path[MAX_PATH];
  DWORD length = ::GetModuleFileNameW(nullptr, module_path, MAX_PATH);
  if (length > 0) {
    g_service_args.emplace_back(WideToUtf8(module_path));
  } else {
    g_service_args.emplace_back("cert-ctrl");
  }

  if (argc > 1 && argv != nullptr) {
    for (DWORD i = 1; i < argc; ++i) {
      g_service_args.emplace_back(WideToUtf8(argv[i]));
    }
  }

  bool has_keep_running = false;
  for (const auto &arg : g_service_args) {
    if (arg == "--keep-running") {
      has_keep_running = true;
      break;
    }
  }
  if (!has_keep_running) {
    g_service_args.emplace_back("--keep-running");
  }

  g_service_arg_ptrs.reserve(g_service_args.size() + 1);
  for (auto &entry : g_service_args) {
    g_service_arg_ptrs.push_back(const_cast<char *>(entry.data()));
  }
  g_service_arg_ptrs.push_back(nullptr);
}

void ReportServiceStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint) {
  if (!g_status_handle) {
    return;
  }
  g_service_status.dwCurrentState = current_state;
  g_service_status.dwWin32ExitCode = exit_code;
  g_service_status.dwWaitHint = wait_hint;

  if (current_state == SERVICE_START_PENDING) {
    g_service_status.dwControlsAccepted = 0;
  } else {
    g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  }

  static DWORD checkpoint = 1;
  if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED) {
    g_service_status.dwCheckPoint = 0;
    checkpoint = 1;
  } else {
    g_service_status.dwCheckPoint = checkpoint++;
  }

  if (!::SetServiceStatus(g_status_handle, &g_service_status)) {
    std::cerr << "SetServiceStatus failed: " << ::GetLastError() << std::endl;
  }
}

DWORD RunAgent() {
  int argc = static_cast<int>(g_service_arg_ptrs.size() - 1);
  return static_cast<DWORD>(RunCertCtrlApplication(argc, g_service_arg_ptrs.data()));
}

DWORD WINAPI ServiceWorkerThread(LPVOID /*param*/) {
  DWORD exit_code = RunAgent();
  return exit_code;
}

void WINAPI ServiceCtrlHandler(DWORD control) {
  switch (control) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN:
    if (!g_stop_requested.exchange(true)) {
      ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
      certctrl::request_shutdown();
    }
    break;
  default:
    break;
  }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
  g_service_status = {};
  g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_service_status.dwServiceSpecificExitCode = NO_ERROR;
  g_stop_requested.store(false);

  g_status_handle = ::RegisterServiceCtrlHandlerW(kServiceName, ServiceCtrlHandler);
  if (!g_status_handle) {
    return;
  }

  ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

  BuildServiceArguments(argc, argv);

  g_worker_thread = ::CreateThread(nullptr, 0, ServiceWorkerThread, nullptr, 0, nullptr);
  if (!g_worker_thread) {
    ReportServiceStatus(SERVICE_STOPPED, ::GetLastError(), 0);
    return;
  }

  ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

  ::WaitForSingleObject(g_worker_thread, INFINITE);

  DWORD thread_exit_code = NO_ERROR;
  ::GetExitCodeThread(g_worker_thread, &thread_exit_code);
  ::CloseHandle(g_worker_thread);
  g_worker_thread = nullptr;

  ReportServiceStatus(SERVICE_STOPPED, thread_exit_code, 0);
}

} // namespace

bool run_windows_service_if_available(int /*argc*/, char * /*argv*/[]) {
  SERVICE_TABLE_ENTRYW service_table[] = {
      {kServiceName, ServiceMain}, {nullptr, nullptr}};

  if (::StartServiceCtrlDispatcherW(service_table)) {
    return true;
  }

  DWORD error = ::GetLastError();
  if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
    return false;
  }

  std::cerr << "StartServiceCtrlDispatcherW failed: " << error << std::endl;
  return false;
}

#else

bool run_windows_service_if_available(int, char **) { return false; }

#endif
