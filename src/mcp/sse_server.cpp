#include "mcp/sse_server.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "mcp/mcp_server.h"
#include "util/strutil.h"
#include "util/version.h"

#pragma comment(lib, "ws2_32.lib")

namespace aj {

namespace {

constexpr size_t kMaxHeaderBytes = 32 * 1024;
constexpr size_t kMaxBodyBytes = 8u << 20;  // same cap as the stdio transport

// ------------------------------------------------------------- socket helpers

bool send_all(SOCKET s, const void* data, size_t n) {
    const char* p = (const char*)data;
    while (n) {
        int sent = ::send(s, p, (int)n, 0);
        if (sent <= 0) return false;
        p += sent;
        n -= (size_t)sent;
    }
    return true;
}

bool recv_line(SOCKET s, std::string& out, size_t cap) {
    out.clear();
    char c = 0;
    while (out.size() < cap) {
        int got = ::recv(s, &c, 1, 0);
        if (got <= 0) return false;
        if (c == '\n') {
            if (!out.empty() && out.back() == '\r') out.pop_back();
            return true;
        }
        out += c;
    }
    return false;  // header line longer than the cap: not our client
}

// Reads exactly the request head (request line + headers) and then
// Content-Length bytes of body. Returns false on any protocol/socket error.
bool recv_request(SOCKET s, std::string& method, std::string& path, std::string& query,
                  std::string& headers, std::string& body) {
    std::string reqline;
    if (!recv_line(s, reqline, kMaxHeaderBytes)) return false;
    {
        size_t sp1 = reqline.find(' ');
        size_t sp2 = sp1 == std::string::npos ? std::string::npos : reqline.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) return false;
        method = reqline.substr(0, sp1);
        std::string target = reqline.substr(sp1 + 1, sp2 - sp1 - 1);
        size_t q = target.find('?');
        if (q == std::string::npos) {
            path = target;
            query.clear();
        } else {
            path = target.substr(0, q);
            query = target.substr(q + 1);
        }
    }
    headers.clear();
    size_t content_length = 0;
    bool chunked = false;
    while (true) {
        std::string line;
        if (!recv_line(s, line, kMaxHeaderBytes)) return false;
        if (line.empty()) break;
        std::string low = to_lower(line);
        if (starts_with(low, "content-length:"))
            content_length = (size_t)strtoull(line.c_str() + 15, nullptr, 10);
        else if (starts_with(low, "transfer-encoding:") && low.find("chunked") != std::string::npos)
            chunked = true;
        headers += line;
        headers += "\n";
    }
    if (chunked) return false;  // not produced by any MCP client
    if (content_length > kMaxBodyBytes) return false;
    body.resize(content_length);
    size_t got = 0;
    while (got < content_length) {
        int r = ::recv(s, body.data() + got, (int)(content_length - got), 0);
        if (r <= 0) return false;
        got += (size_t)r;
    }
    return true;
}

std::string header_value(const std::string& headers, const std::string& name) {
    // case-insensitive scan of "Name: value" lines
    std::string want = to_lower(name) + ":";
    size_t pos = 0;
    while (pos < headers.size()) {
        size_t eol = headers.find('\n', pos);
        if (eol == std::string::npos) eol = headers.size();
        std::string line = headers.substr(pos, eol - pos);
        if (starts_with(to_lower(line), want)) {
            std::string v = trim(line.substr(want.size()));
            return v;
        }
        pos = eol + 1;
    }
    return {};
}

std::string query_value(const std::string& query, const std::string& key) {
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        std::string kv = query.substr(pos, amp - pos);
        size_t eq = kv.find('=');
        if (eq != std::string::npos && kv.substr(0, eq) == key) return kv.substr(eq + 1);
        pos = amp + 1;
    }
    return {};
}

const char* kCors =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Authorization, Content-Type, MCP-Session-Id, Last-Event-ID\r\n";

bool send_response(SOCKET s, const char* status, const char* content_type, const void* body,
                   size_t body_len) {
    std::string head = fmt("HTTP/1.1 %s\r\n"
                           "Content-Type: %s\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: close\r\n"
                           "%s"
                           "\r\n",
                           status, content_type, body_len, kCors);
    // single send: head and body split across writes made simple clients that
    // recv() once see a response without its body
    std::string packet = std::move(head);
    packet.append((const char*)body, body_len);
    return send_all(s, packet.data(), packet.size());
}

// ------------------------------------------------------------------ sessions

// One legacy-transport client: an open event stream plus an outgoing frame
// queue drained by the thread that owns the socket.
struct SseSession {
    std::string id;
    SOCKET s = INVALID_SOCKET;
    std::mutex mu;
    std::condition_variable cv;
    std::deque<std::string> frames;  // complete "event: ...\ndata: ...\n\n" blocks
    bool closed = false;

    void push(const std::string& frame) {
        {
            std::lock_guard<std::mutex> lk(mu);
            if (closed) return;
            frames.push_back(frame);
        }
        cv.notify_one();
    }
};

std::string random_hex(size_t nbytes) {
    std::vector<uint8_t> buf(nbytes);
    bool ok = false;
    HMODULE bcrypt = GetModuleHandleW(L"bcrypt.dll");
    if (bcrypt) {
        using Fn = LONG(WINAPI*)(void*, ULONG, ULONG);
        Fn fn = (Fn)GetProcAddress(bcrypt, "BCryptGenRandom");
        if (fn) ok = fn(buf.data(), (ULONG)nbytes, 0) >= 0;
    }
    if (!ok) {
        // fallback: time + cheap PRNG (session ids, not secrets)
        srand((unsigned)(GetTickCount64() ^ (uintptr_t)&buf));
        for (auto& b : buf) b = (uint8_t)(rand() & 0xFF);
    }
    std::string out;
    out.reserve(nbytes * 2);
    for (uint8_t b : buf) out += fmt("%02x", b);
    return out;
}

}  // namespace

std::string mcp_random_hex(size_t nbytes) { return random_hex(nbytes); }

namespace {

// -------------------------------------------------------------- the server

struct Pending {
    std::string msg;
    std::shared_ptr<SseSession> sse;  // reply goes onto the event stream
    // ...or back to the POST that carried it (streamable HTTP)
    std::shared_ptr<std::mutex> post_mu;
    std::shared_ptr<std::condition_variable> post_cv;
    std::shared_ptr<bool> post_ready;
    std::shared_ptr<std::string> post_reply;
};

struct ServerState {
    std::string token;  // empty = no auth (loopback use)
    std::mutex mu;
    std::condition_variable cv;
    std::deque<Pending> queue;
    std::map<std::string, std::shared_ptr<SseSession>> sessions;

    bool authorized(const std::string& headers, const std::string& query) const {
        if (token.empty()) return true;
        std::string auth = header_value(headers, "Authorization");
        if (starts_with(to_lower(auth), "bearer ") && auth.substr(7) == token) return true;
        // SSE clients that cannot set headers (browser EventSource) use the URL
        return query_value(query, "token") == token;
    }

    void enqueue(Pending p) {
        {
            std::lock_guard<std::mutex> lk(mu);
            queue.push_back(std::move(p));
        }
        cv.notify_one();
    }
};

// Handles one accepted connection. SSE streams stay in this thread until the
// client goes away; everything else is one request -> one response.
void serve_connection(SOCKET s, ServerState& st) {
    std::string method, path, query, headers, body;
    if (!recv_request(s, method, path, query, headers, body)) {
        closesocket(s);
        return;
    }

    if (method == "OPTIONS") {
        send_response(s, "204 No Content", "text/plain", nullptr, 0);
        closesocket(s);
        return;
    }
    if (!st.authorized(headers, query)) {
        send_response(s, "401 Unauthorized", "text/plain", "bad or missing token\n", 15);
        closesocket(s);
        return;
    }

    if (method == "GET" && path == "/") {
        std::string t = "aidbg " AIDBG_VERSION " MCP server\n/sse /messages /mcp\n";
        send_response(s, "200 OK", "text/plain", t.data(), t.size());
        closesocket(s);
        return;
    }

    // ---- legacy SSE transport: open the event stream ----------------------
    if (method == "GET" && path == "/sse") {
        auto session = std::make_shared<SseSession>();
        session->id = random_hex(12);
        session->s = s;
        {
            std::lock_guard<std::mutex> lk(st.mu);
            st.sessions[session->id] = session;
        }
        std::string head =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n" +
            std::string(kCors) + "\r\n";
        std::string endpoint = fmt("event: endpoint\ndata: /messages?sessionId=%s\n\n",
                                   session->id.c_str());
        if (!send_all(s, head.data(), head.size()) || !send_all(s, endpoint.data(), endpoint.size())) {
            std::lock_guard<std::mutex> lk(st.mu);
            st.sessions.erase(session->id);
            closesocket(s);
            return;
        }

        // Drain outgoing frames until the client disconnects. A comment every
        // 15 s keeps intermediaries from timing the stream out.
        while (true) {
            std::string frame;
            {
                std::unique_lock<std::mutex> lk(session->mu);
                session->cv.wait_for(lk, std::chrono::seconds(15), [&] {
                    return session->closed || !session->frames.empty();
                });
                if (session->closed) break;
                if (session->frames.empty()) {
                    frame = ": ping\n\n";
                } else {
                    frame = std::move(session->frames.front());
                    session->frames.pop_front();
                }
            }
            if (!send_all(s, frame.data(), frame.size())) break;
        }
        {
            std::lock_guard<std::mutex> lk(session->mu);
            session->closed = true;
        }
        {
            std::lock_guard<std::mutex> lk(st.mu);
            st.sessions.erase(session->id);
        }
        closesocket(s);
        return;
    }

    // ---- legacy SSE transport: message ingress ----------------------------
    if (method == "POST" && path == "/messages") {
        std::string sid = query_value(query, "sessionId");
        std::shared_ptr<SseSession> session;
        {
            std::lock_guard<std::mutex> lk(st.mu);
            auto it = st.sessions.find(sid);
            if (it != st.sessions.end()) session = it->second;
        }
        if (!session) {
            send_response(s, "404 Not Found", "text/plain", "no such session\n", 16);
            closesocket(s);
            return;
        }
        Pending p;
        p.msg = body;
        p.sse = session;
        st.enqueue(std::move(p));
        // The reply arrives on the event stream; the POST itself is done.
        send_response(s, "202 Accepted", "text/plain", nullptr, 0);
        closesocket(s);
        return;
    }

    // ---- streamable HTTP transport ----------------------------------------
    if (method == "POST" && path == "/mcp") {
        if (body.empty()) {
            send_response(s, "400 Bad Request", "text/plain", "empty body\n", 11);
            closesocket(s);
            return;
        }
        // The reply channel must outlive the move into the queue.
        auto mu = std::make_shared<std::mutex>();
        auto cv = std::make_shared<std::condition_variable>();
        auto ready = std::make_shared<bool>(false);
        auto reply = std::make_shared<std::string>();
        Pending p;
        p.msg = body;
        p.post_mu = mu;
        p.post_cv = cv;
        p.post_ready = ready;
        p.post_reply = reply;
        st.enqueue(std::move(p));
        // The dispatcher replies whenever the (possibly long) command ends.
        std::unique_lock<std::mutex> lk(*mu);
        cv->wait(lk, [&] { return *ready; });
        std::string out = std::move(*reply);
        if (out.empty())
            send_response(s, "202 Accepted", "text/plain", nullptr, 0);  // notification
        else
            send_response(s, "200 OK", "application/json", out.data(), out.size());
        closesocket(s);
        return;
    }
    if (method == "GET" && path == "/mcp") {
        // This server never initiates traffic, so it offers no server-side
        // stream; the spec allows answering the GET with 405.
        send_response(s, "405 Method Not Allowed", "text/plain",
                      "POST JSON-RPC messages to /mcp\n", 31);
        closesocket(s);
        return;
    }
    if (method == "DELETE" && path == "/mcp") {
        send_response(s, "200 OK", "text/plain", nullptr, 0);
        closesocket(s);
        return;
    }

    send_response(s, "404 Not Found", "text/plain", "unknown route\n", 15);
    closesocket(s);
}

}  // namespace

int run_mcp_http_server(CliConfig& cfg, const std::string& bind_addr, uint16_t port,
                        const std::string& token) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "[aidbg] WSAStartup failed\n");
        return 1;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* ai = nullptr;
    if (getaddrinfo(bind_addr.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0 || !ai) {
        std::fprintf(stderr, "[aidbg] cannot resolve bind address '%s'\n", bind_addr.c_str());
        WSACleanup();
        return 1;
    }
    SOCKET listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (listener == INVALID_SOCKET) {
        std::fprintf(stderr, "[aidbg] socket() failed: %d\n", WSAGetLastError());
        freeaddrinfo(ai);
        WSACleanup();
        return 1;
    }
    BOOL reuse = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    if (bind(listener, ai->ai_addr, (int)ai->ai_addrlen) != 0) {
        std::fprintf(stderr, "[aidbg] bind(%s:%u) failed: %d\n", bind_addr.c_str(), port,
                     WSAGetLastError());
        closesocket(listener);
        freeaddrinfo(ai);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(ai);
    if (listen(listener, 16) != 0) {
        std::fprintf(stderr, "[aidbg] listen() failed: %d\n", WSAGetLastError());
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    static ServerState st;  // outlives detached connection threads
    st.token = token;

    // The dispatcher owns the engine (single-threaded, like the debug loop).
    Engine eng;
    mcp_setup_engine(eng, cfg);
    bool initialized = false;

    std::fprintf(stderr, "[aidbg] MCP server listening on http://%s:%u\n",
                 bind_addr.c_str(), port);
    std::fprintf(stderr, "[aidbg]   GET  /sse        (SSE transport)\n");
    std::fprintf(stderr, "[aidbg]   POST /mcp        (streamable HTTP)\n");
    if (token.empty())
        std::fprintf(stderr, "[aidbg]   auth: none (loopback only recommended)\n");
    else
        std::fprintf(stderr, "[aidbg]   auth: Authorization: Bearer %s\n", token.c_str());
    std::fflush(stderr);

    std::thread acceptor([&] {
        for (;;) {
            SOCKET c = accept(listener, nullptr, nullptr);
            if (c == INVALID_SOCKET) continue;
            std::thread(&serve_connection, c, std::ref(st)).detach();
        }
    });
    acceptor.detach();

    // Main thread: serialize every JSON-RPC message against the engine and
    // route the reply back where it came from.
    for (;;) {
        Pending p;
        {
            std::unique_lock<std::mutex> lk(st.mu);
            st.cv.wait(lk, [&] { return !st.queue.empty(); });
            p = std::move(st.queue.front());
            st.queue.pop_front();
        }
        Json resp = mcp_handle_message(eng, cfg, p.msg, initialized);
        if (p.sse) {
            if (!resp.is_null())
                p.sse->push(fmt("event: message\ndata: %s\n\n", resp.dump().c_str()));
            continue;
        }
        if (p.post_ready) {
            std::lock_guard<std::mutex> lk(*p.post_mu);
            *p.post_reply = resp.is_null() ? std::string() : resp.dump();
            *p.post_ready = true;
            p.post_cv->notify_one();
        }
    }
}

}  // namespace aj
