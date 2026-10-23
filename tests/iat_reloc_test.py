"""P8 regression: keepbase dump with a non-zero slide AND a destroyed import
table must still rebuild the imports (the scan must see runtime pointers
before the relocation repair rewrites them)."""
import json
import subprocess
import sys
import time

proc = subprocess.Popen(
    [r"build\aidbg.exe", "--json", "--aslr"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    cwd=r"D:\crack\debug\code\aidbg", text=True, encoding="utf-8", errors="replace")


def cmd(line):
    proc.stdin.write(line + "\n")
    proc.stdin.flush()
    while True:
        raw = proc.stdout.readline()
        if not raw:
            raise RuntimeError("eof")
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        j = json.loads(raw)
        if "cmd" in j:
            return j


fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name, detail)
    if not cond:
        fails.append(name)


try:
    cmd("file tests/target.exe")
    cmd("run")
    j = cmd("eval target.exe+0")
    base = int(j["data"]["value"], 16)
    check("relocated session", base != 0x140000000, hex(base))

    # destroy the original import directory (packed-binary simulation)
    j = cmd(f"write {hex(base + 0xb5398)} " + "58 " * 20)
    check("corrupt import dir", j["ok"], j.get("error", {}).get("message", ""))

    j = cmd("dump tests/out_combo.exe keepbase")
    check("dump ok", j["ok"], j.get("error", {}).get("message", ""))
    imp = j["data"].get("imports", {})
    rel = j["data"].get("relocation", {})
    check("imports rebuilt despite non-zero slide", imp.get("module_count", 0) > 0,
          f"modules={imp.get('module_count')} thunks={imp.get('thunks')} "
          f"note={imp.get('note', '')}")
    check("relocation still restored", rel.get("image_base_restored") is True,
          str(rel.get("entries_unrelocated")))
finally:
    try:
        cmd("kill")
    except Exception:
        pass
    proc.stdin.close()
    proc.wait(timeout=10)

print("RESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
