"""End-to-end test of the aidbg MCP HTTP/SSE server (loopback)."""
import json
import socket
import subprocess
import sys
import threading
import time

PORT = 8791
TOKEN = "testtok-1234"
BASE = ("127.0.0.1", PORT)

proc = subprocess.Popen(
    [r"build\aidbg.exe", "--mcp", "--port", str(PORT), "--token", TOKEN],
    cwd=r"D:\crack\debug\code\aidbg",
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name, detail)
    if not cond:
        fails.append(name)


def wait_port(timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(BASE, timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def http_post(path, body, token=TOKEN, headers_extra=None):
    s = socket.create_connection(BASE, timeout=60)
    hdr = f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
    if token:
        hdr += f"Authorization: Bearer {token}\r\n"
    if headers_extra:
        hdr += headers_extra
    payload = body.encode()
    hdr += f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    s.sendall(hdr.encode() + payload)
    resp = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        resp += chunk
    s.close()
    head, _, rest = resp.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode(errors="replace")
    return status, rest.decode(errors="replace")


try:
    check("server listens", wait_port())

    # ---- auth -------------------------------------------------------------
    st, _ = http_post("/mcp", "{}", token="wrong")
    check("wrong token rejected", "401" in st, st)
    st, _ = http_post("/mcp", "{}", token=None)
    check("missing token rejected", "401" in st, st)

    # ---- streamable HTTP --------------------------------------------------
    st, body = http_post("/mcp", json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18"}}))
    j = json.loads(body)
    check("initialize over streamable HTTP",
          "200" in st and j["result"]["serverInfo"]["name"] == "aidbg",
          f'{st} {j.get("result", {}).get("serverInfo")}')

    http_post("/mcp", json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    st, body = http_post("/mcp", json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "aidbg_command", "arguments": {"command": "version"}}}))
    inner = json.loads(json.loads(body)["result"]["content"][0]["text"])
    check("tools/call over streamable HTTP", inner["ok"] and inner["data"]["version"],
          inner["data"].get("version"))

    st, body = http_post("/mcp", json.dumps(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}))
    names = [t["name"] for t in json.loads(body)["result"]["tools"]]
    check("tools/list", "aidbg_session" in names and "aidbg_execute" in names,
          f"{len(names)} tools")

    st, _ = http_post("/mcp", json.dumps({"jsonrpc": "2.0", "id": 4, "method": "bogus/x"}))
    check("unknown method -> -32601", "-32601" in _, f"{st} {_[:60]}")

    # ---- a real debug round trip over HTTP --------------------------------
    st, body = http_post("/mcp", json.dumps(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "aidbg_session",
                    "arguments": {"action": "file", "exe": r"tests\target.exe"}}}))
    inner = json.loads(json.loads(body)["result"]["content"][0]["text"])
    check("set target over HTTP", inner["ok"], inner.get("error", {}).get("message"))
    st, body = http_post("/mcp", json.dumps(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
         "params": {"name": "aidbg_session", "arguments": {"action": "run"}}}))
    inner = json.loads(json.loads(body)["result"]["content"][0]["text"])
    check("run over HTTP", inner["ok"], inner.get("error", {}).get("message"))
    st, body = http_post("/mcp", json.dumps(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": "aidbg_execute", "arguments": {"action": "continue", "timeout_ms": 8000}}}))
    inner = json.loads(json.loads(body)["result"]["content"][0]["text"])
    check("run+continue to exit over HTTP",
          inner["ok"] and inner["data"]["stop"]["reason"] == "exit",
          inner["data"].get("stop", {}).get("text"))

    # ---- legacy SSE transport ---------------------------------------------
    sse = socket.create_connection(BASE, timeout=30)
    sse.sendall(f"GET /sse HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n"
                "Accept: text/event-stream\r\n\r\n".encode())
    sse.settimeout(20)
    buf = b""
    endpoint_path = None
    replies = []

    def reader():
        global buf, endpoint_path
        while True:
            try:
                chunk = sse.recv(65536)
            except socket.timeout:
                return
            if not chunk:
                return
            buf += chunk
            text = buf.decode(errors="replace")
            # endpoint event
            if endpoint_path is None and "event: endpoint" in text:
                for line in text.splitlines():
                    if line.startswith("data: /messages"):
                        endpoint_path = line[6:].strip()
            # message events -> replies list
            while "event: message" in buf.decode(errors="replace"):
                text = buf.decode(errors="replace")
                i = text.find("event: message")
                seg = text[i:]
                j = seg.find("\n\n")
                if j < 0:
                    break
                for line in seg[:j].splitlines():
                    if line.startswith("data: "):
                        replies.append(json.loads(line[6:]))
                buf = (text[:i] + seg[j + 2:]).encode()

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    deadline = time.time() + 10
    while endpoint_path is None and time.time() < deadline:
        time.sleep(0.1)
    check("SSE endpoint event received", endpoint_path is not None, str(endpoint_path))

    st, _ = http_post(endpoint_path, json.dumps(
        {"jsonrpc": "2.0", "id": 10, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}}))
    check("SSE POST accepted (202)", "202" in st, st)

    deadline = time.time() + 10
    while not replies and time.time() < deadline:
        time.sleep(0.1)
    ok = bool(replies) and replies[0]["result"]["serverInfo"]["name"] == "aidbg"
    check("SSE response arrives on the stream", ok,
          str(replies[0])[:80] if replies else "no reply")

    # second round trip on the same stream (session stays alive)
    replies.clear()
    http_post(endpoint_path, json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}))
    st, _ = http_post(endpoint_path, json.dumps(
        {"jsonrpc": "2.0", "id": 11, "method": "ping"}))
    deadline = time.time() + 10
    while not replies and time.time() < deadline:
        time.sleep(0.1)
    check("SSE ping round trip", bool(replies) and replies[0].get("id") == 11,
          str(replies[0])[:60] if replies else "no reply")
    sse.close()

    # ---- health -----------------------------------------------------------
    def http_get_raw(path, token=None):
        s = socket.create_connection(BASE, timeout=5)
        hdr = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
        if token:
            hdr += f"Authorization: Bearer {token}\r\n"
        s.sendall((hdr + "\r\n").encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        return resp.decode(errors="replace")

    resp = http_get_raw("/", TOKEN)
    check("health endpoint", "200" in resp and "aidbg" in resp, resp.splitlines()[0])
    resp = http_get_raw("/")
    check("health also requires the token", "401" in resp, resp.splitlines()[0])

finally:
    proc.kill()
    proc.wait()

print("RESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
