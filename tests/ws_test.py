import json
import subprocess
import sys
import time

proc = subprocess.Popen(
    [r"build\aidbg.exe", "--json"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    cwd=r"D:\crack\debug\code\aidbg", text=True, encoding="utf-8", errors="replace")


def send(line):
    proc.stdin.write(line + "\n")
    proc.stdin.flush()


def recv(timeout=30):
    out = []
    while True:
        line = proc.stdout.readline()
        if not line:
            return out
        line = line.strip()
        if not line.startswith("{"):
            continue
        j = json.loads(line)
        out.append(j)
        # wait for a command reply (events flow before it)
        if "cmd" in j:
            return j


def cmd(line, timeout=30):
    send(line)
    return recv(timeout)


fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name, detail)
    if not cond:
        fails.append(name)


cmd("file tests/tickpair.exe")
cmd("run")
cmd("continue 1500")           # both processes tick for 1.5 s
j = cmd("pause")
check("pause stops in multi-process session",
      j["data"].get("stop", {}).get("text") == "paused by request")

j = cmd("processes")
procs = [p for p in j["data"]["processes"] if not p.get("system")]
cur = next(p for p in procs if p.get("current"))
other = next(p for p in procs if not p.get("current"))
check("two debuggee processes", len(procs) == 2, f"{[p['name'] for p in procs]}")

# --- current process must be frozen while stopped -------------------------
a1 = cmd("read g_ticks 4")["data"]["bytes"]
cmd("sleep 1200")
a2 = cmd("read g_ticks 4")["data"]["bytes"]
check("current process frozen while stopped", a1 == a2, f"{a1} -> {a2}")

# --- the OTHER process must be frozen too, and its symbols resolve --------
j = cmd(f"process {other['pid']}")
check("switch to other process", j["ok"], str(j.get("error", {}).get("message")))
e = cmd("eval g_ticks")
addr = e["data"].get("value") if e["ok"] else None
check("per-process symbol resolves in other process", bool(addr),
      str(e.get("error", {}).get("message")))
b1 = cmd("read g_ticks 4")["data"]["bytes"]
cmd("sleep 1200")
b2 = cmd("read g_ticks 4")["data"]["bytes"]
check("other process frozen while stopped", b1 == b2, f"{b1} -> {b2}")

# --- parent and child bases differ (per-process symbol scenario) ----------
pa = cmd("processes")  # still current=other
send("eval g_ticks")
ea = recv()["data"]["value"]
cmd(f"process {cur['pid']}")
send("eval g_ticks")
eb = recv()["data"]["value"]
check("same symbol, different base per process", ea != eb, f"child={ea} parent={eb}")

# --- resume must run everything to natural completion (no deadlock) -------
cmd(f"process {cur['pid']}")
for _ in range(20):
    j = cmd("continue 2000")
    txt = j["data"].get("stop", {}).get("text", "")
    if "exited" in txt:
        break
check("session runs to natural exit", "exited" in j["data"].get("stop", {}).get("text", ""),
      j["data"]["stop"]["text"])

proc.stdin.close()
proc.wait(timeout=15)
print("RESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
