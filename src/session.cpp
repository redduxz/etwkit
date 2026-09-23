#include "session.h"
#include <evntprov.h>

static const ULONG kEtwBufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 256;

static GUID GuidFromString(const wchar_t* s) {
    GUID g{};
    IIDFromString(const_cast<LPWSTR>(s), &g);
    return g;
}

const std::vector<ProviderSpec>& TraceSession::BuiltInProviders() {
    static const std::vector<ProviderSpec> p = {
        {L"process",  GuidFromString(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"), 5, 0x10 | 0x20 | 0x40},
        {L"network",  GuidFromString(L"{7DD42A49-5329-4832-8DFD-43D979153A88}"), 5, 0x10 | 0x20},
        {L"file",     GuidFromString(L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}"), 5, 0x10 | 0x20 | 0x40 | 0x80 | 0x100},
        {L"registry", GuidFromString(L"{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"), 5, 0xFFFFFFFFFFFFFFFFULL},
        {L"dns",      GuidFromString(L"{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"), 5, 0xFFFFFFFFFFFFFFFFULL},
        {L"powershell", GuidFromString(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"), 5, 0xFFFFFFFFFFFFFFFFULL},
    };
    return p;
}

TraceSession::TraceSession() = default;

TraceSession::~TraceSession() {
    Stop();
}

VOID WINAPI TraceSession::RecordThunk(PEVENT_RECORD rec) {
    auto* self = static_cast<TraceSession*>(rec->UserContext);
    if (self && self->cb_) self->cb_(rec);
}

DWORD WINAPI TraceSession::ConsumeProc(LPVOID ctx) {
    auto* self = static_cast<TraceSession*>(ctx);
    ProcessTrace(&self->traceHandle_, 1, nullptr, nullptr);
    return 0;
}

bool TraceSession::Start(const std::wstring& sessionName,
                         const std::vector<ProviderSpec>& providers,
                         EventCallback cb) {
    if (running_) return false;
    cb_ = std::move(cb);
    sessionName_ = sessionName;

    std::vector<BYTE> buf(kEtwBufferSize, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
    props->Wnode.BufferSize = kEtwBufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(0, sessionName_.c_str(), props, EVENT_TRACE_CONTROL_STOP);

    ULONG status = StartTraceW(&sessionHandle_, sessionName_.c_str(), props);
    if (status != ERROR_SUCCESS) return false;

    for (const auto& p : providers) {
        ENABLE_TRACE_PARAMETERS params{};
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        GUID g = p.guid;
        EnableTraceEx2(sessionHandle_, &g, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                       p.level, p.anyKeywords, 0, 0, &params);
    }

    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = const_cast<LPWSTR>(sessionName_.c_str());
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = &TraceSession::RecordThunk;
    log.Context = this;

    traceHandle_ = OpenTraceW(&log);
    if (traceHandle_ == INVALID_PROCESSTRACE_HANDLE) {
        ControlTraceW(sessionHandle_, sessionName_.c_str(), props, EVENT_TRACE_CONTROL_STOP);
        return false;
    }

    running_ = true;
    consumeThread_ = CreateThread(nullptr, 0, &TraceSession::ConsumeProc, this, 0, nullptr);
    return consumeThread_ != nullptr;
}

void TraceSession::Stop() {
    if (!running_) return;
    running_ = false;
    CloseTrace(traceHandle_);
    std::vector<BYTE> buf(kEtwBufferSize, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
    props->Wnode.BufferSize = kEtwBufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(sessionHandle_, sessionName_.c_str(), props, EVENT_TRACE_CONTROL_STOP);
    if (consumeThread_) {
        WaitForSingleObject(consumeThread_, 5000);
        CloseHandle(consumeThread_);
        consumeThread_ = nullptr;
    }
}
