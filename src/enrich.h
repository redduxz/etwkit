#pragma once

#include <windows.h>
#include <string>
#include <unordered_map>

class ProcCache {
public:
    ProcCache();
    std::wstring ImageName(DWORD pid);
    std::wstring ImagePath(DWORD pid);

private:
    std::wstring Lookup(DWORD pid, bool fullPath);
    std::unordered_map<DWORD, std::wstring> names_;
    std::unordered_map<DWORD, std::wstring> paths_;
    ULONGLONG lastSweep_{0};
};
