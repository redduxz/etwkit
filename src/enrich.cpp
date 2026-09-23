#include "enrich.h"
#include <tlhelp32.h>

ProcCache::ProcCache() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            names_[pe.th32ProcessID] = pe.szExeFile;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    lastSweep_ = GetTickCount64();
}

std::wstring ProcCache::ImageName(DWORD pid) {
    if (pid == 0) return L"idle";
    auto it = names_.find(pid);
    if (it != names_.end()) return it->second;
    return Lookup(pid, false);
}

std::wstring ProcCache::ImagePath(DWORD pid) {
    auto it = paths_.find(pid);
    if (it != paths_.end()) return it->second;
    return Lookup(pid, true);
}

std::wstring ProcCache::Lookup(DWORD pid, bool fullPath) {
    std::wstring result;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        wchar_t buf[MAX_PATH];
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
            result.assign(buf, sz);
            if (!fullPath) {
                size_t pos = result.find_last_of(L'\\');
                if (pos != std::wstring::npos) result = result.substr(pos + 1);
            }
        }
        CloseHandle(h);
    }
    if (result.empty()) result = L"pid:" + std::to_wstring(pid);
    if (fullPath) paths_[pid] = result; else names_[pid] = result;
    return result;
}
