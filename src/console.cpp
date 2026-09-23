#include "console.h"
#include "decoder.h"
#include <tdh.h>
#include <cstdio>
#include <vector>

static bool g_color = false;

void ConsoleRenderInit() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        g_color = true;
    }
}

static const char* LevelColor(BYTE level) {
    switch (level) {
    case 1: return "\x1b[91m";
    case 2: return "\x1b[91m";
    case 3: return "\x1b[93m";
    case 4: return "\x1b[96m";
    default: return "\x1b[90m";
    }
}

static std::wstring FirstProps(PEVENT_RECORD rec) {
    ULONG size = 0;
    if (TdhGetEventInformation(rec, 0, nullptr, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER)
        return L"";
    std::vector<BYTE> buf(size);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());
    if (TdhGetEventInformation(rec, 0, nullptr, info, &size) != ERROR_SUCCESS)
        return L"";

    std::wstring out;
    USHORT n = info->TopLevelPropertyCount < 5 ? info->TopLevelPropertyCount : 5;
    for (USHORT i = 0; i < n; i++) {
        auto* prop = &info->EventPropertyInfoArray[i];
        std::wstring name = prop->NameOffset
            ? reinterpret_cast<wchar_t*>(buf.data() + prop->NameOffset) : L"?";
        PROPERTY_DATA_DESCRIPTOR dd{};
        dd.PropertyName = reinterpret_cast<ULONGLONG>(
            reinterpret_cast<BYTE*>(info) + prop->NameOffset);
        dd.ArrayIndex = ALL_DATA;
        ULONG sz = 0;
        if (TdhGetPropertySize(rec, 0, nullptr, 1, &dd, &sz) != ERROR_SUCCESS || sz > 512)
            continue;
        std::vector<BYTE> data(sz);
        if (TdhGetProperty(rec, 0, nullptr, 1, &dd, sz, data.data()) != ERROR_SUCCESS)
            continue;
        USHORT t = prop->nonStructType.InType;
        std::wstring v;
        if (t == TDH_INTYPE_UNICODESTRING) v = reinterpret_cast<wchar_t*>(data.data());
        else if (t == TDH_INTYPE_UINT32) v = std::to_wstring(*reinterpret_cast<uint32_t*>(data.data()));
        else if (t == TDH_INTYPE_UINT64) v = std::to_wstring(*reinterpret_cast<uint64_t*>(data.data()));
        else if (t == TDH_INTYPE_INT32) v = std::to_wstring(*reinterpret_cast<int32_t*>(data.data()));
        else if (t == TDH_INTYPE_INT64) v = std::to_wstring(*reinterpret_cast<int64_t*>(data.data()));
        else if (t == TDH_INTYPE_UINT16) v = std::to_wstring(*reinterpret_cast<uint16_t*>(data.data()));
        else if (t == TDH_INTYPE_UINT8) v = std::to_wstring(*reinterpret_cast<uint8_t*>(data.data()));
        else continue;
        if (!out.empty()) out += L"  ";
        out += name + L"=" + v;
    }
    if (out.size() > 160) out = out.substr(0, 160) + L"...";
    return out;
}

static void Put(const std::wstring& w) {
    DWORD n = 0;
    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), w.data(), (DWORD)w.size(), &n, nullptr);
}

void ConsoleRender(PEVENT_RECORD rec, ProcCache& cache) {
    FILETIME ft{};
    ft.dwLowDateTime = rec->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = rec->EventHeader.TimeStamp.HighPart;
    std::wstring ts = IsoTimestamp(ft).substr(11, 12);

    ULONG size = 0;
    std::wstring prov, task;
    if (TdhGetEventInformation(rec, 0, nullptr, nullptr, &size) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buf(size);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());
        if (TdhGetEventInformation(rec, 0, nullptr, info, &size) == ERROR_SUCCESS) {
            if (info->ProviderNameOffset)
                prov = reinterpret_cast<wchar_t*>(buf.data() + info->ProviderNameOffset);
            if (info->TaskNameOffset)
                task = reinterpret_cast<wchar_t*>(buf.data() + info->TaskNameOffset);
        }
    }
    if (prov.rfind(L"Microsoft-Windows-", 0) == 0) prov = prov.substr(18);
    if (task.empty()) task = L"ev" + std::to_wstring(rec->EventHeader.EventDescriptor.Id);

    std::wstring img = cache.ImageName(rec->EventHeader.ProcessId);
    std::wstring props = FirstProps(rec);

    wchar_t line[1024];
    if (g_color) {
        swprintf(line, 1024, L"%s%S\x1b[0m \x1b[36m%-28S\x1b[0m %-5u %-22S %-24S %S\n",
            LevelColor(rec->EventHeader.EventDescriptor.Level),
            ts.c_str(), prov.c_str(), rec->EventHeader.ProcessId,
            task.c_str(), img.c_str(), props.c_str());
    } else {
        swprintf(line, 1024, L"%S %-28S %-5u %-22S %-24S %S\n",
            ts.c_str(), prov.c_str(), rec->EventHeader.ProcessId,
            task.c_str(), img.c_str(), props.c_str());
    }
    Put(line);
}
