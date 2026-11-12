#include "http.hpp"

#include <poll.h>
#include <sys/socket.h>

#include <cstring>

namespace sp {
namespace {

std::string response(int code, const char* reason, const char* type, const std::string& body) {
    std::string r = "HTTP/1.1 " + std::to_string(code) + " " + reason + "\r\n";
    r += std::string("Content-Type: ") + type + "\r\n";
    r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    r += "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
    return r + body;
}

}

HttpServer::HttpServer(uint16_t port, std::function<std::string()> status) : requested_(port), status_(std::move(status)) {}

HttpServer::~HttpServer() { stop(); }

void HttpServer::start() {
    listen_ = listen_tcp(requested_, &port_);
    thread_ = std::thread([this] { loop(); });
}

void HttpServer::stop() {
    stop_ = true;
    if (thread_.joinable()) thread_.join();
    workers_.join_all();
}

void HttpServer::loop() {
    while (!stop_) {
        Fd c = accept_tcp(listen_.get(), 100, nullptr);
        if (!c.valid()) continue;
        if (workers_.running() >= 32) continue;
        auto holder = std::make_shared<Fd>(std::move(c));
        workers_.spawn([this, holder] { handle(std::move(*holder)); });
    }
}

void HttpServer::handle(Fd fd) {
    try {
        std::string req;
        uint64_t deadline = now_ms() + 2000;
        while (req.find("\r\n\r\n") == std::string::npos && req.size() < 8192) {
            uint64_t now = now_ms();
            if (now >= deadline || !wait_readable(fd.get(), static_cast<int>(deadline - now))) return;
            char buf[1024];
            ssize_t r = ::recv(fd.get(), buf, sizeof buf, 0);
            if (r <= 0) return;
            req.append(buf, static_cast<size_t>(r));
        }
        size_t eol = req.find("\r\n");
        if (eol == std::string::npos) return;
        std::string line = req.substr(0, eol);
        size_t s1 = line.find(' '), s2 = line.rfind(' ');
        std::string out;
        if (s1 == std::string::npos || s2 == s1) {
            out = response(400, "Bad Request", "text/plain; charset=utf-8", "requisicao invalida\n");
        } else if (line.substr(0, s1) != "GET") {
            out = response(405, "Method Not Allowed", "text/plain; charset=utf-8", "metodo nao permitido\n");
        } else {
            std::string path = line.substr(s1 + 1, s2 - s1 - 1);
            size_t q = path.find('?');
            if (q != std::string::npos) path.resize(q);
            if (path == "/" || path == "/index.html") out = response(200, "OK", "text/html; charset=utf-8", dashboard_html());
            else if (path == "/api/status") out = response(200, "OK", "application/json; charset=utf-8", status_());
            else out = response(404, "Not Found", "text/plain; charset=utf-8", "nao encontrado\n");
        }
        send_all(fd.get(), reinterpret_cast<const uint8_t*>(out.data()), out.size(), 3000);
    } catch (const std::exception&) {
    }
}

}
