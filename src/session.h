#pragma once

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <functional>
#include <string>
#include <vector>

struct ProviderSpec {
    std::wstring name;
    GUID guid;
    UCHAR level;
    ULONGLONG anyKeywords;
};

class TraceSession {
public:
    using EventCallback = std::function<void(PEVENT_RECORD)>;

    TraceSession();
    ~TraceSession();

    bool Start(const std::wstring& sessionName,
               const std::vector<ProviderSpec>& providers,
               EventCallback cb);
    void Stop();
    bool Running() const { return running_; }

    static const std::vector<ProviderSpec>& BuiltInProviders();

private:
    static VOID WINAPI RecordThunk(PEVENT_RECORD rec);

    TRACEHANDLE sessionHandle_{};
    TRACEHANDLE traceHandle_{};
    EventCallback cb_;
    bool running_{false};
    HANDLE consumeThread_{};
    std::wstring sessionName_;

    static DWORD WINAPI ConsumeProc(LPVOID ctx);
};
