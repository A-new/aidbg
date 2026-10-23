"""Verifies the keepbase dump restores the preferred base and un-applies
relocations (dump taken from an ASLR-relocated module, slide != 0)."""
import json
import struct
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
    check("target relocated (ASLR session)", base != 0x140000000, hex(base))
    j = cmd("modules")
    tgt = next(m for m in j["data"]["modules"] if m["name"].startswith("target"))
    check("module reports relocated", tgt.get("relocated") is True, str(tgt.get("slide")))

    j = cmd("dump tests/out_reloc.exe keepbase")
    check("dump ok", j["ok"], j.get("error", {}).get("message", ""))
    rel = j["data"].get("relocation", {})
    check("un-relocation ran", rel.get("image_base_restored") is True, json.dumps(rel)[:120])
    slide = int(rel.get("slide", "0x0"), 16)
    check("slide non-zero in this session", slide != 0, hex(slide))
finally:
    try:
        cmd("kill")
    except Exception:
        pass
    proc.stdin.close()
    proc.wait(timeout=10)

# --- verify the dumped file -----------------------------------------------
data = open("tests/out_reloc.exe", "rb").read()
e = struct.unpack_from("<I", data, 0x3C)[0]
opt = e + 24
imgbase = struct.unpack_from("<Q", data, opt + 0x18)[0]
sizeimg = struct.unpack_from("<I", data, opt + 0x38)[0]
check("ImageBase restored to preferred", imgbase == 0x140000000, hex(imgbase))

nsec = struct.unpack_from("<H", data, e + 6)[0]
optsz = struct.unpack_from("<H", data, e + 20)[0]
secs = []
sh = e + 4 + 20 + optsz
for i in range(nsec):
    s = sh + i * 40
    name = data[s:s + 8].rstrip(b"\0").decode(errors="replace")
    vsz, va, rsz, rptr = struct.unpack_from("<IIII", data, s + 8)
    secs.append((name, va, vsz, rptr, rsz))


def r2o(rva):
    for _, va, vsz, rptr, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return rptr + (rva - va)
    return None


rel_rva, rel_sz = struct.unpack_from("<II", data, opt + 0x70 + 5 * 8)
fixed = total = bad = 0
off = r2o(rel_rva)
pos = 0
while pos + 8 <= rel_sz:
    page, block = struct.unpack_from("<II", data, off + pos)
    if block < 8:
        break
    for k in range(8, block - 1, 2):
        entry = struct.unpack_from("<H", data, off + pos + k)[0]
        typ, ofs = entry >> 12, entry & 0xFFF
        if typ not in (3, 10):
            continue
        toff = r2o(page + ofs)
        if toff is None:
            continue
        v = struct.unpack_from("<Q", data, toff)[0]
        total += 1
        if 0x140000000 <= v < 0x140000000 + sizeimg:
            fixed += 1
        elif v and not (0x140000000 <= v < 0x140000000 + sizeimg) and v > 0x7FF000000000:
            bad += 1
    pos += block
print(f"reloc targets: {total}, preferred-range values: {fixed}, other-module ptrs: {bad}")
# every reloc target of a clean image must be back in the preferred range;
# anything left at the slid (or foreign) address is an un-applied relocation
check("relocated pointers restored to preferred range", total > 0 and fixed == total,
      f"{fixed}/{total} in preferred range, {bad} foreign")

print("RESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
