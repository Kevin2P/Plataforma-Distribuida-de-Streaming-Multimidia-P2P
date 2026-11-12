#include "util.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <random>

namespace sp {
namespace {
std::atomic<int> g_level{1};
std::mutex g_log_mu;
const uint64_t g_start_ms = now_ms();
}

uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

uint64_t wall_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

Bytes random_bytes(size_t n) {
    Bytes out(n);
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t got = 0;
    if (fd >= 0) {
        while (got < n) {
            ssize_t r = ::read(fd, out.data() + got, n - got);
            if (r <= 0) break;
            got += static_cast<size_t>(r);
        }
        ::close(fd);
    }
    if (got < n) {
        std::random_device rd;
        for (; got < n; got++) out[got] = static_cast<uint8_t>(rd());
    }
    return out;
}

bool valid_id(const std::string& s) {
    if (s.empty() || s.size() > 32) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool valid_name(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    size_t i = 0;
    while (i < s.size()) {
        uint8_t c = static_cast<uint8_t>(s[i]);
        size_t extra;
        if (c < 0x20 || c == 0x7f) return false;
        if (c < 0x80) extra = 0;
        else if (c >= 0xC2 && c <= 0xDF) extra = 1;
        else if (c >= 0xE0 && c <= 0xEF) extra = 2;
        else if (c >= 0xF0 && c <= 0xF4) extra = 3;
        else return false;
        // Faixa do segundo byte: exclui os controles C1 (U+0080 a U+009F), codificacoes longas
        // demais, surrogates (U+D800 a U+DFFF) e valores acima de U+10FFFF.
        uint8_t lo = 0x80, hi = 0xBF;
        if (c == 0xC2 || c == 0xE0) lo = 0xA0;
        else if (c == 0xED) hi = 0x9F;
        else if (c == 0xF0) lo = 0x90;
        else if (c == 0xF4) hi = 0x8F;
        for (size_t k = 1; k <= extra; k++) {
            if (i + k >= s.size()) return false;
            uint8_t b = static_cast<uint8_t>(s[i + k]);
            if (k == 1 ? (b < lo || b > hi) : (b & 0xC0) != 0x80) return false;
        }
        i += extra + 1;
    }
    return true;
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char ch : s) {
        uint8_t c = static_cast<uint8_t>(ch);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(ch);
                }
        }
    }
    return out;
}

void set_log_level(LogLevel level) { g_level.store(static_cast<int>(level)); }
LogLevel log_level() { return static_cast<LogLevel>(g_level.load()); }

void logf(LogLevel level, const char* tag, const char* fmt, ...) {
    if (static_cast<int>(level) > g_level.load()) return;
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    std::lock_guard<std::mutex> lock(g_log_mu);
    std::fprintf(stderr, "[%8.3fs] %-8s %s\n", static_cast<double>(now_ms() - g_start_ms) / 1000.0, tag, msg);
}

void ThreadSet::reap_locked() {
    for (auto it = slots_.begin(); it != slots_.end();) {
        if (it->done->load()) {
            if (it->thread.joinable()) it->thread.join();
            it = slots_.erase(it);
        } else {
            ++it;
        }
    }
}

void ThreadSet::spawn(std::function<void()> fn) {
    std::lock_guard<std::mutex> lock(mu_);
    reap_locked();
    auto done = std::make_shared<std::atomic<bool>>(false);
    slots_.push_back(Slot{std::thread([fn = std::move(fn), done] {
                              fn();
                              done->store(true);
                          }),
                          done});
}

void ThreadSet::join_all() {
    std::list<Slot> taken;
    {
        std::lock_guard<std::mutex> lock(mu_);
        taken.swap(slots_);
    }
    for (auto& s : taken)
        if (s.thread.joinable()) s.thread.join();
}

size_t ThreadSet::running() {
    std::lock_guard<std::mutex> lock(mu_);
    reap_locked();
    return slots_.size();
}

}
