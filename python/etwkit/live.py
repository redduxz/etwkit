import json
import os
import time
from typing import Iterator


def tail(path: str, poll: float = 0.25) -> Iterator[dict]:
    while not os.path.exists(path):
        time.sleep(poll)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll)
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def fmt(e: dict) -> str:
    ts = e.get("ts", "")[11:23]
    prov = e.get("provider", "")[:32]
    task = e.get("task", "")
    pid = e.get("pid", "")
    props = e.get("props", {})
    bits = " ".join(
        f"{k}={str(v)[:60]}" for k, v in list(props.items())[:4]
    )
    return f"{ts} {prov:32} pid={pid:<6} {task:20} {bits}"


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="etwkit-live")
    ap.add_argument("file")
    ap.add_argument("--provider")
    ap.add_argument("--task")
    ap.add_argument("--pid", type=int)
    a = ap.parse_args()
    for e in tail(a.file):
        if a.provider and e.get("provider") != a.provider:
            continue
        if a.task and e.get("task") != a.task:
            continue
        if a.pid is not None and e.get("pid") != a.pid:
            continue
        print(fmt(e), flush=True)


if __name__ == "__main__":
    main()
