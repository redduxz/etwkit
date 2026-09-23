#include "session.h"
#include "decoder.h"
#include "console.h"
#include "enrich.h"

#include <cstdio>
#include <csignal>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

static volatile bool g_stop = false;

BOOL WINAPI OnCtrl(DWORD) { g_stop = true; return TRUE; }

static std::string Narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static bool IsElevated() {
    BOOL admin = FALSE;
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION e{};
        DWORD sz = 0;
        if (GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &sz))
            admin = e.TokenIsElevated;
        CloseHandle(tok);
    }
    return admin == TRUE;
}

static void Usage() {
    puts("etwkit - ETW telemetry to JSONL\n"
         "\n"
         "  etwkit trace [-o out.jsonl] [-p process,network,dns,file,registry,powershell] [-d seconds]\n"
         "  etwkit watch [-p providers] [-d seconds]\n"
         "  etwkit providers\n"
         "\n"
         "  -o   output file (default: stdout)\n"
         "  -p   comma list of providers (default: process,network,dns)\n"
         "  -d   stop after N seconds (default: until Ctrl+C)\n"
         "\n"
         "Kernel providers require elevation. Run from an admin prompt.");
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { Usage(); return 1; }

    std::wstring cmd = argv[1];
    if (cmd == L"providers") {
        for (auto& p : TraceSession::BuiltInProviders())
            wprintf(L"%s  %s\n", p.name.c_str(), GuidToString(p.guid).c_str());
        return 0;
    }
    if (cmd == L"watch") {
        std::wstring provList = L"process,network,dns";
        int duration = 0;
        for (int i = 2; i + 1 < argc; i += 2) {
            std::wstring a = argv[i];
            if (a == L"-p") provList = argv[i + 1];
            else if (a == L"-d") duration = _wtoi(argv[i + 1]);
        }
        std::vector<ProviderSpec> selected;
        std::wstring needle = L"," + provList + L",";
        for (auto& p : TraceSession::BuiltInProviders())
            if (needle.find(L"," + p.name + L",") != std::wstring::npos) selected.push_back(p);
        if (selected.empty()) { puts("no matching providers"); return 1; }
        if (!IsElevated()) puts("warning: not elevated - kernel providers may fail");

        ConsoleRenderInit();
        ProcCache cache;
        SetConsoleCtrlHandler(OnCtrl, TRUE);

        TraceSession ts;
        bool ok = ts.Start(L"etwkit-watch", selected, [&](PEVENT_RECORD rec) {
            ConsoleRender(rec, cache);
        });
        if (!ok) { puts("failed to start trace session (need admin?)"); return 1; }
        fprintf(stderr, "watching %zu providers (Ctrl+C to stop)\n", selected.size());
        auto t0 = GetTickCount64();
        while (!g_stop) {
            if (duration && (GetTickCount64() - t0) / 1000 >= (ULONGLONG)duration) break;
            Sleep(200);
        }
        ts.Stop();
        return 0;
    }
    if (cmd != L"trace") { Usage(); return 1; }

    std::wstring outPath;
    std::wstring provList = L"process,network,dns";
    int duration = 0;
    for (int i = 2; i + 1 < argc; i += 2) {
        std::wstring a = argv[i];
        if (a == L"-o") outPath = argv[i + 1];
        else if (a == L"-p") provList = argv[i + 1];
        else if (a == L"-d") duration = _wtoi(argv[i + 1]);
    }

    std::vector<ProviderSpec> selected;
    for (auto& p : TraceSession::BuiltInProviders()) {
        std::wstring needle = L"," + provList + L",";
        if (needle.find(L"," + p.name + L",") != std::wstring::npos)
            selected.push_back(p);
    }
    if (selected.empty()) {
        puts("no matching providers");
        return 1;
    }

    if (!IsElevated())
        puts("warning: not elevated - kernel providers may fail");

    std::ofstream ofs;
    std::wofstream wofs;
    bool toFile = !outPath.empty();
    if (toFile) ofs.open(Narrow(outPath), std::ios::binary | std::ios::trunc);

    SetConsoleCtrlHandler(OnCtrl, TRUE);

    TraceSession ts;
    unsigned long long n = 0;
    bool ok = ts.Start(L"etwkit", selected, [&](PEVENT_RECORD rec) {
        std::wstring j = DecodeEventToJson(rec);
        if (j.empty()) return;
        std::string line = Narrow(j) + "\n";
        if (toFile) ofs.write(line.data(), line.size());
        else fputs(line.c_str(), stdout);
        if (++n % 10000 == 0) {
            fprintf(stderr, "\r%llu events", n);
            if (toFile) ofs.flush();
        }
    });

    if (!ok) {
        puts("failed to start trace session (need admin?)");
        return 1;
    }

    fprintf(stderr, "tracing %zu providers -> %s (Ctrl+C to stop)\n",
        selected.size(), toFile ? Narrow(outPath).c_str() : "stdout");

    auto t0 = GetTickCount64();
    while (!g_stop) {
        if (duration && (GetTickCount64() - t0) / 1000 >= (ULONGLONG)duration) break;
        Sleep(200);
    }

    ts.Stop();
    if (toFile) ofs.close();
    fprintf(stderr, "\n%llu events\n", n);
    return 0;
}
