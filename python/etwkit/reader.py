import json
from typing import Callable, Iterator, Optional


def iter_events(path: str) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def read(path: str) -> list[dict]:
    return list(iter_events(path))


def filter_events(
    events,
    provider: Optional[str] = None,
    task: Optional[str] = None,
    pid: Optional[int] = None,
    predicate: Optional[Callable[[dict], bool]] = None,
) -> list[dict]:
    out = []
    for e in events:
        if provider and e.get("provider") != provider:
            continue
        if task and e.get("task") != task:
            continue
        if pid is not None and e.get("pid") != pid:
            continue
        if predicate and not predicate(e):
            continue
        out.append(e)
    return out


def process_tree(events) -> dict:
    tree = {}
    for e in events:
        if e.get("task") not in ("ProcessStart", "ProcessStop", "Start", "Stop"):
            continue
        props = e.get("props", {})
        pid = props.get("ProcessID") or props.get("ProcessId") or e.get("pid")
        ppid = props.get("ParentID") or props.get("ParentProcessId")
        name = props.get("ImageName") or props.get("ImageFileName") or ""
        cmdline = props.get("CommandLine") or ""
        tree[pid] = {"ppid": ppid, "image": name, "cmdline": cmdline}
    return tree


def summary(events) -> dict:
    from collections import Counter
    providers = Counter(e.get("provider") for e in events)
    tasks = Counter(e.get("task") for e in events if e.get("task"))
    pids = Counter(e.get("pid") for e in events)
    return {
        "total": len(events),
        "by_provider": dict(providers.most_common(20)),
        "by_task": dict(tasks.most_common(20)),
        "top_pids": dict(pids.most_common(10)),
    }
