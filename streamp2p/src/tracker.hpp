#pragma once
#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "http.hpp"
#include "protocol.hpp"
#include "util.hpp"

namespace sp {

constexpr size_t kMaxPeers = 1024;
constexpr size_t kMaxContents = 256;

struct TrackerStats {
    uint64_t registrations = 0, replaced = 0, publishes = 0, heartbeats = 0, lookups = 0, lists = 0;
    uint64_t expired = 0, disconnects = 0, auth_failures = 0, protocol_errors = 0;
};

class TrackerState {
public:
    explicit TrackerState(uint64_t ttl_ms) : ttl_ms_(ttl_ms), started_wall_(wall_ms()), started_mono_(now_ms()) {}
    uint64_t register_peer(const std::string& id, const std::string& host, uint16_t tcp, uint16_t udp, uint64_t now);
    bool is_active(uint64_t session) const;
    bool publish(uint64_t session, const Manifest& m, const Bytes& bitmap, uint64_t now);
    bool heartbeat(uint64_t session, const HeartbeatMsg& hb, uint64_t now, std::vector<Digest>& unknown);
    bool lookup(uint64_t session, const Digest& id, LookupReply& out);
    std::vector<ContentSummary> list();
    void remove(uint64_t session, const std::string& reason);
    size_t expire(uint64_t now);
    void note_auth_failure(const std::string& host);
    void note_protocol_error(const std::string& who);
    TrackerStats stats() const;
    size_t peer_count() const;
    size_t content_count() const;
    std::string status_json(uint64_t now) const;
    uint64_t ttl_ms() const { return ttl_ms_; }

private:
    struct Peer {
        uint64_t session = 0;
        std::string id, host;
        uint16_t tcp = 0, udp = 0;
        uint64_t joined = 0, last_seen = 0, up = 0, down = 0;
        std::map<std::string, Bitmap> holds;
    };
    struct Event {
        uint64_t wall;
        std::string text;
    };
    void event_locked(const std::string& text);
    void gc_contents_locked();
    void remove_locked(uint64_t session, const std::string& reason);

    uint64_t ttl_ms_;
    uint64_t started_wall_;
    uint64_t started_mono_;
    mutable std::mutex mu_;
    uint64_t next_session_ = 0;
    std::map<uint64_t, Peer> peers_;
    std::map<std::string, uint64_t> by_id_;
    std::map<std::string, Manifest> contents_;
    std::deque<Event> events_;
    TrackerStats stats_;
};

class Tracker {
public:
    struct Config {
        Bytes psk;
        uint16_t port = 7000;
        int web_port = -1;
        uint64_t ttl_ms = 6000;
    };
    explicit Tracker(Config cfg);
    ~Tracker();
    void start();
    void stop();
    uint16_t port() const { return port_; }
    uint16_t web_port() const { return http_ ? http_->port() : 0; }
    TrackerState& state() { return state_; }

private:
    void accept_loop();
    void reaper_loop();
    void serve(Fd fd, std::string host);

    Config cfg_;
    TrackerState state_;
    Fd listen_;
    uint16_t port_ = 0;
    std::unique_ptr<HttpServer> http_;
    ThreadSet threads_;
    std::atomic<bool> stop_{false};
    std::thread acceptor_, reaper_;
    std::mutex conns_mu_;
    std::map<uint64_t, std::shared_ptr<SecureChannel>> conns_;
};

}
