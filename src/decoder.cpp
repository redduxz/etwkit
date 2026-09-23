#include "decoder.h"
#include <tdh.h>
#include <sddl.h>
#include <vector>
#include <array>
#include <cstdio>

#pragma comment(lib, "tdh.lib")

static std::wstring JsonEscape(const std::wstring& in) {
    std::wstring out;
    out.reserve(in.size() + 8);
    for (wchar_t c : in) {
        switch (c) {
        case L'"':  out += L"\\\""; break;
        case L'\\': out += L"\\\\"; break;
        case L'\b': out += L"\\b";  break;
        case L'\f': out += L"\\f";  break;
        case L'\n': out += L"\\n";  break;
        case L'\r': out += L"\\r";  break;
        case L'\t': out += L"\\t";  break;
        default:
            if (c < 0x20) {
                wchar_t buf[8];
                swprintf(buf, 8, L"\\u%04x", c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

std::wstring GuidToString(const GUID& g) {
    wchar_t buf[64];
    swprintf(buf, 64, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

std::wstring IsoTimestamp(const FILETIME& ft) {
    FILETIME local = ft;
    SYSTEMTIME st;
    FileTimeToSystemTime(&local, &st);
    wchar_t buf[32];
    swprintf(buf, 32, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static std::wstring PropertyToString(PEVENT_RECORD rec,
                                   PTRACE_EVENT_INFO info,
                                   USHORT propIndex,
                                   ULONG arrayIndex) {
    auto* prop = &info->EventPropertyInfoArray[propIndex];

    PROPERTY_DATA_DESCRIPTOR dd{};
    dd.PropertyName = reinterpret_cast<ULONGLONG>(
        reinterpret_cast<BYTE*>(info) + prop->NameOffset);
    dd.ArrayIndex = arrayIndex;

    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, nullptr, 1, &dd, &size) != ERROR_SUCCESS || size == 0)
        return L"";

    std::vector<BYTE> data(size);
    ULONG consumed = size;
    USHORT inType = prop->nonStructType.InType;

    if (TdhGetProperty(rec, 0, nullptr, 1, &dd, consumed, data.data()) != ERROR_SUCCESS)
        return L"";

    switch (inType) {
    case TDH_INTYPE_UNICODESTRING: {
        std::wstring s(reinterpret_cast<wchar_t*>(data.data()));
        return L"\"" + JsonEscape(s) + L"\"";
    }
    case TDH_INTYPE_ANSISTRING: {
        std::string s(reinterpret_cast<char*>(data.data()));
        std::wstring ws(s.begin(), s.end());
        return L"\"" + JsonEscape(ws) + L"\"";
    }
    case TDH_INTYPE_INT8:   return std::to_wstring(*reinterpret_cast<int8_t*>(data.data()));
    case TDH_INTYPE_UINT8:  return std::to_wstring(*reinterpret_cast<uint8_t*>(data.data()));
    case TDH_INTYPE_INT16:  return std::to_wstring(*reinterpret_cast<int16_t*>(data.data()));
    case TDH_INTYPE_UINT16: return std::to_wstring(*reinterpret_cast<uint16_t*>(data.data()));
    case TDH_INTYPE_INT32:  return std::to_wstring(*reinterpret_cast<int32_t*>(data.data()));
    case TDH_INTYPE_UINT32: return std::to_wstring(*reinterpret_cast<uint32_t*>(data.data()));
    case TDH_INTYPE_INT64:  return std::to_wstring(*reinterpret_cast<int64_t*>(data.data()));
    case TDH_INTYPE_UINT64: return std::to_wstring(*reinterpret_cast<uint64_t*>(data.data()));
    case TDH_INTYPE_FLOAT: {
        wchar_t b[32]; swprintf(b, 32, L"%g", *reinterpret_cast<float*>(data.data())); return b;
    }
    case TDH_INTYPE_DOUBLE: {
        wchar_t b[32]; swprintf(b, 32, L"%g", *reinterpret_cast<double*>(data.data())); return b;
    }
    case TDH_INTYPE_BOOLEAN:
        return *reinterpret_cast<uint32_t*>(data.data()) ? L"true" : L"false";
    case TDH_INTYPE_GUID:
        return L"\"" + GuidToString(*reinterpret_cast<GUID*>(data.data())) + L"\"";
    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_HEXINT64: {
        wchar_t b[24];
        swprintf(b, 24, L"0x%llx", *reinterpret_cast<unsigned long long*>(data.data()));
        return L"\"" + std::wstring(b) + L"\"";
    }
    case TDH_INTYPE_HEXINT32: {
        wchar_t b[16];
        swprintf(b, 16, L"0x%x", *reinterpret_cast<unsigned int*>(data.data()));
        return L"\"" + std::wstring(b) + L"\"";
    }
    case TDH_INTYPE_FILETIME:
    case TDH_INTYPE_SYSTEMTIME:
        if (inType == TDH_INTYPE_FILETIME) {
            return L"\"" + IsoTimestamp(*reinterpret_cast<FILETIME*>(data.data())) + L"\"";
        }
        return L"null";
    case TDH_INTYPE_SID: {
        wchar_t* sidStr = nullptr;
        std::wstring out = L"null";
        if (ConvertSidToStringSidW(data.data(), &sidStr)) {
            out = L"\"" + std::wstring(sidStr) + L"\"";
            LocalFree(sidStr);
        }
        return out;
    }
    default: {
        std::wstring hex;
        const wchar_t* d = L"0123456789abcdef";
        for (ULONG i = 0; i < consumed && i < 64; i++) {
            hex += d[data[i] >> 4];
            hex += d[data[i] & 0xF];
        }
        return L"\"hex:" + hex + L"\"";
    }
    }
}

std::wstring DecodeEventToJson(PEVENT_RECORD rec) {
    ULONG size = 0;
    if (TdhGetEventInformation(rec, 0, nullptr, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER)
        return L"";

    std::vector<BYTE> buf(size);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());
    if (TdhGetEventInformation(rec, 0, nullptr, info, &size) != ERROR_SUCCESS)
        return L"";

    std::wstring provider = (info->ProviderNameOffset)
        ? reinterpret_cast<wchar_t*>(buf.data() + info->ProviderNameOffset)
        : GuidToString(rec->EventHeader.ProviderId);

    std::wstring taskName, opcodeName;
    if (info->TaskNameOffset)
        taskName = reinterpret_cast<wchar_t*>(buf.data() + info->TaskNameOffset);
    if (info->OpcodeNameOffset)
        opcodeName = reinterpret_cast<wchar_t*>(buf.data() + info->OpcodeNameOffset);

    FILETIME ft{};
    ft.dwLowDateTime = rec->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = rec->EventHeader.TimeStamp.HighPart;
    std::wstring json = L"{\"ts\":\"" + IsoTimestamp(ft) + L"\"";
    json += L",\"provider\":\"" + JsonEscape(provider) + L"\"";
    json += L",\"event_id\":" + std::to_wstring(rec->EventHeader.EventDescriptor.Id);
    json += L",\"level\":" + std::to_wstring(rec->EventHeader.EventDescriptor.Level);
    json += L",\"pid\":" + std::to_wstring(rec->EventHeader.ProcessId);
    json += L",\"tid\":" + std::to_wstring(rec->EventHeader.ThreadId);
    if (!taskName.empty())   json += L",\"task\":\"" + JsonEscape(taskName) + L"\"";
    if (!opcodeName.empty()) json += L",\"opcode\":\"" + JsonEscape(opcodeName) + L"\"";

    json += L",\"props\":{";
    USHORT count = info->TopLevelPropertyCount;
    for (USHORT i = 0; i < count; i++) {
        auto* prop = &info->EventPropertyInfoArray[i];
        std::wstring name = prop->NameOffset
            ? reinterpret_cast<wchar_t*>(buf.data() + prop->NameOffset)
            : L"p" + std::to_wstring(i);
        if (i) json += L",";
        json += L"\"" + JsonEscape(name) + L"\":";

        bool isArray = (prop->count > 1) || (prop->Flags & PropertyParamCount) != 0;
        if (isArray) {
            json += L"[";
            for (ULONG e = 0; e < 32; e++) {
                PROPERTY_DATA_DESCRIPTOR dd{};
                dd.PropertyName = reinterpret_cast<ULONGLONG>(
                    reinterpret_cast<BYTE*>(info) + prop->NameOffset);
                dd.ArrayIndex = e;
                ULONG es = 0;
                if (TdhGetPropertySize(rec, 0, nullptr, 1, &dd, &es) != ERROR_SUCCESS) break;
                if (e) json += L",";
                json += PropertyToString(rec, info, i, e);
            }
            json += L"]";
        } else {
            json += PropertyToString(rec, info, i, ULONG_MAX);
        }
    }
    json += L"}}";
    return json;
}
