#pragma once
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "protocol.hpp"
#include "store.hpp"

namespace sp {

class TrackerClient {
public:
    struct Config {
        Endpoint tracker;
        Bytes psk;
        std::string id;
        uint16_t tcp_port = 0;
        uint16_t udp_port = 0;
        uint32_t max_heartbeat_ms = 200;
        bool share = true;
    };
    using Counters = std::function<void(uint64_t& uploaded, uint64_t& downloaded)>;

    TrackerClient(Config cfg, ChunkStore& store, Counters counters);
    ~TrackerClient();
    void start();
    void stop();
    bool connected() const { return connected_.load(); }
    bool wait_connected(int timeout_ms);
    bool lookup(const Digest& id, LookupReply& out);
    bool list(std::vector<ContentSummary>& out);
    uint64_t sessions() const { return sessions_.load(); }

private:
    void loop();
    void run_session(const std::shared_ptr<SecureChannel>& ch);
    bool rpc(Msg type, const Bytes& payload, Frame& reply, int timeout_ms);
    void heartbeat(const std::shared_ptr<SecureChannel>& ch);
    void publish_content(const Digest& id);
    bool interruptible_sleep(uint32_t ms);

    Config cfg_;
    ChunkStore& store_;
    Counters counters_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> connected_{false};
    std::atomic<bool> broken_{false};
    std::atomic<uint64_t> sessions_{0};
    std::thread thread_;
    std::mutex io_mu_;
    std::shared_ptr<SecureChannel> chan_;
    std::mutex wake_mu_;
    std::condition_variable wake_cv_;
};

}
