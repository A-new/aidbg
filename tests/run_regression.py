#!/usr/bin/env python3
"""Regression runner for aidbg.

Every ``tests/*.ajs`` script must be classified here, either as a maintained
regression with the target it needs, or as an explicitly ignored ad-hoc script
with a reason. An unclassified script fails the run, so a newly added test can
never be forgotten.

Checks per script: terminates within the timeout, exits 0, every stdout line is
valid UTF-8 JSON (the JSONL contract), and no line carries ``"ok":false``.

    python -I tests/run_regression.py            # .ajs regressions
    python -I tests/run_regression.py --e2e      # plus the python end-to-end tests
    python -I tests/run_regression.py --only hide
    python -I tests/run_regression.py --list

Exit code 0 only when everything passed.
"""
import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AIDBG = os.path.join(ROOT, "build", "aidbg.exe")

# script name (without .ajs) -> target passed via --exe
REGRESSIONS = {
    "hide_std": "tests/antidbg_probe.exe",
    "hide_detect": "tests/antidbg_probe.exe",
    "hide_nofake": "tests/antidbg_probe.exe",
    "hide_b": "tests/antidbg_probe.exe",
    "reg_basic": "tests/target.exe",
    "reg_patch": "tests/target.exe",
    "reg_detach": "tests/antidbg_probe.exe",
    "sysfile": "tests/target.exe",
    "feat_bp": "tests/target.exe",
    "feat_bphit": "tests/target.exe",
    "feat_notes": "tests/target.exe",
    "feat_xmm": "tests/target.exe",
    "reg_types": "tests/types_test.exe",
    "reg_children": "tests/spawner.exe",
    "fixbase": "tests/selfcheck.exe",
    "dlltest": "tests/sample_dll.dll",
    "dlltest32": "tests/sample_dll32.dll",
    "dll_debug": "tests/sample_dll.dll",
    "hide_ini": "tests/target.exe",
}

# Explicitly out of the runner, with the reason.
IGNORED = {
    "disasm_check": "ad-hoc probe with hardcoded system addresses",
    "disasm_crash": "ad-hoc probe with hardcoded system addresses",
    "fix1": "ad-hoc snapshot repro; writes snap_test.bin (command forms changed)",
    "fix24": "negative test: asserts execution control inside bpcmd is refused (ok:false expected)",
    "hide_b2": "ad-hoc hook-matrix diagnostic (needs hand timing)",
    "hide_b3": "ad-hoc hook-matrix diagnostic (needs hand timing)",
    "hide_basic64": "ad-hoc diagnostic; the probe does not exit under the basic profile",
    "hide_diag": "ad-hoc diagnostic (timeout based)",
    "hide_b32basic": "ad-hoc diagnostic; 32-bit probe does not exit under the basic profile",
    "hide_b32qip": "ad-hoc diagnostic (timeout based)",
    "hide_diag32": "ad-hoc diagnostic (timeout based)",
    "hide_scyl": "loads ScyllaHide's ini from an absolute path outside the repo",
}

# python end-to-end tests, driven the same way
E2E = {
    "tests/dbgstring_test.py": 120,
    "tests/reloc_test.py": 300,
    "tests/iat_reloc_test.py": 300,
    "tests/ws_test.py": 180,
    "tests/http_mcp_test.py": 180,
}


class Failure(Exception):
    pass


def check_jsonl(stdout):
    """Strictly validate every output line and count failed envelopes."""
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Failure("stdout is not valid UTF-8: %s" % e)
    failures = []
    lines = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        lines += 1
        try:
            j = json.loads(line)
        except json.JSONDecodeError as e:
            raise Failure("non-JSON output line %d: %s (%r)" % (lines, e, line[:120]))
        if isinstance(j, dict) and j.get("ok") is False:
            err = j.get("error") or {}
            failures.append("%s: %s" % (j.get("cmd", "?"), err.get("message", "")))
    return lines, failures


def run_ajs(name, exe, timeout):
    script = os.path.join(ROOT, "tests", name + ".ajs")
    cmd = [AIDBG, "--json", "--exe", exe, "--script", script]
    try:
        res = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Failure("timeout after %ss" % timeout)
    if res.returncode != 0:
        raise Failure("exit code %d" % res.returncode)
    lines, failures = check_jsonl(res.stdout)
    if failures:
        raise Failure("%d command failure(s): %s" % (len(failures), "; ".join(failures[:3])))
    if lines == 0:
        raise Failure("no output")
    return "%d commands" % lines


def run_py(path, timeout):
    try:
        res = subprocess.run([sys.executable, "-I", os.path.join(ROOT, path)],
                             cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Failure("timeout after %ss" % timeout)
    out = res.stdout.decode("utf-8", "replace").strip().splitlines()
    if res.returncode != 0:
        tail = "\n        ".join(out[-5:])
        raise Failure("exit code %d\n        %s" % (res.returncode, tail))
    return out[-1] if out else "ok"


def classify():
    """Every .ajs in tests/ must be in REGRESSIONS or IGNORED."""
    present = sorted(os.path.splitext(f)[0] for f in os.listdir(os.path.join(ROOT, "tests"))
                     if f.endswith(".ajs"))
    known = set(REGRESSIONS) | set(IGNORED)
    return present, [n for n in present if n not in known], sorted(known - set(present))


def main():
    ap = argparse.ArgumentParser(description="aidbg regression runner")
    ap.add_argument("--only", default="", help="run only tests whose name contains this")
    ap.add_argument("--timeout", type=int, default=90, help="per-script timeout (s)")
    ap.add_argument("--e2e", action="store_true", help="also run the python end-to-end tests")
    ap.add_argument("--list", action="store_true", help="show the classification and exit")
    args = ap.parse_args()

    present, unclassified, missing = classify()
    if args.list:
        for n in present:
            if n in REGRESSIONS:
                print("REGRESSION  %-16s %s" % (n, REGRESSIONS[n]))
            elif n in IGNORED:
                print("IGNORED     %-16s %s" % (n, IGNORED[n]))
            else:
                print("UNCLASSIFIED %s" % n)
        for n in missing:
            print("MISSING     %s (classified but no tests/%s.ajs)" % (n, n))
        return 0 if not unclassified and not missing else 1

    if not os.path.isfile(AIDBG):
        print("FAIL build/aidbg.exe not found - run build.bat Release", file=sys.stderr)
        return 2

    failures = []
    ran = 0

    def report(status, name, detail):
        print("%-4s %-18s %s" % (status, name, detail))
        if status != "PASS":
            failures.append(name)

    for name in unclassified:
        report("FAIL", name, "unclassified script - add it to REGRESSIONS or IGNORED")
    for name in missing:
        report("FAIL", name, "classified but tests/%s.ajs does not exist" % name)

    for name, exe in REGRESSIONS.items():
        if args.only and args.only.lower() not in name.lower():
            continue
        ran += 1
        try:
            report("PASS", name, run_ajs(name, exe, args.timeout))
        except Failure as e:
            report("FAIL", name, str(e))

    if args.e2e:
        for path, timeout in E2E.items():
            name = os.path.basename(path)
            if args.only and args.only.lower() not in name.lower():
                continue
            ran += 1
            try:
                report("PASS", name, run_py(path, timeout))
            except Failure as e:
                report("FAIL", name, str(e))

    print("\n%d run, %d failed" % (ran, len(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
