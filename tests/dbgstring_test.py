"""Verifies OutputDebugString handling in the JSONL contract.

The target emits an already-UTF-8 narrow string, an ANSI-code-page narrow
string and a UTF-16 string. Every one must come back as a `debug_string` event
whose text is valid UTF-8 (strict clients reject the line otherwise), and no
event may come from a system helper such as conhost.exe.

`--hide off` is required: the anti-anti-debug profile clears PEB.BeingDebugged,
and kernel32's OutputDebugString only raises the debug-print exception when
that flag is set, so with hide on the target's own debug output is invisible by
design (see dev.md).

tests/dbgstring.exe is built from dbgstring.c (/MT /utf-8, x64).
"""
import json
import subprocess
import sys

ROOT = r"D:\crack\debug\code\aidbg"
EXPECTED = [
    "UTF8 未指定的错误",
    "ANSI 未指定的错误",
    "UNICODE 未指定的错误",
]

proc = subprocess.Popen(
    [r"build\aidbg.exe", "--json", "--hide", "off"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    cwd=ROOT)

events = []
bad_utf8 = []
target_pid = None


def read_until_cmd():
    global target_pid
    while True:
        raw = proc.stdout.readline()
        if not raw:
            raise RuntimeError("eof")
        try:
            line = raw.decode("utf-8")  # strict: invalid bytes are a failure
        except UnicodeDecodeError as e:
            bad_utf8.append(str(e))
            continue
        line = line.strip()
        if not line.startswith("{"):
            continue
        j = json.loads(line)
        if "cmd" in j:
            if j.get("cmd") in ("file", "run") and j.get("ok"):
                target_pid = j.get("data", {}).get("pid", target_pid)
            return j
        if j.get("event") == "debug_string":
            events.append(j)


def cmd(line):
    proc.stdin.write((line + "\n").encode("utf-8"))
    proc.stdin.flush()
    return read_until_cmd()


fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name, detail)
    if not cond:
        fails.append(name)


try:
    cmd("file tests/dbgstring.exe")
    cmd("run")
    j = cmd("continue")
    check("reached exit", j["data"].get("stop", {}).get("reason") == "exit",
          str(j.get("data")))

    texts = [e["text"] for e in events]
    check("all three strings delivered", texts == EXPECTED, repr(texts))
    check("no invalid UTF-8 lines", not bad_utf8, "; ".join(bad_utf8[:3]))
    pids = {e["data"].get("pid") for e in events}
    check("no system-process debug strings",
          target_pid is not None and pids == {target_pid}, str(pids))
finally:
    try:
        proc.stdin.write(b"q\n")
        proc.stdin.flush()
    except Exception:
        pass
    proc.kill()

print("RESULT", "PASS" if not fails else "FAIL", f"({len(fails)} failed)")
sys.exit(0 if not fails else 1)
