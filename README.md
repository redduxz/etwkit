# etwkit

ETW telemetry toolkit: real-time kernel-provider trace -> JSONL, plus a Python reader/live tail.

## build (Windows, VS BuildTools 2022)

    build.bat            # NMake + MSVC via vcvars64
    cmake -B build && cmake --build build   # or your generator of choice

## use

    etwkit providers
    etwkit trace -o out.jsonl -p process,network,dns -d 60
    etwkit watch -p process,network

Kernel providers require an elevated prompt. `watch` renders a live console view;
`trace` writes JSONL for the python sdk:

    pip install ./python
    etwkit-live out.jsonl --task ProcessStart

## layout

- `src/session.*`  real-time ETW session lifecycle
- `src/decoder.*`  TDH -> JSON event decoding
- `src/console.*`  live watch renderer
- `src/enrich.*`   pid -> image name cache
- `python/etwkit/` jsonl reader, filters, tail
