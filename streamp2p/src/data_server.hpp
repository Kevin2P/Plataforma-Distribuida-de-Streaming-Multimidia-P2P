#pragma once
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "emulation.hpp"
#include "protocol.hpp"
#include "store.hpp"
#include "util.hpp"

namespace sp {

class DataServer {
public:
    struct Config {
        std::string id;
        Bytes psk;
        LinkProfile profile;
        uint16_t tcp_port = 0;
        uint16_t udp_port = 0;
        uint32_t udp_rto_ms = 100;
    };
    struct Stats {
        std::atomic<uint64_t> uploaded_bytes{0}, chunks_served{0}, requests{0}, not_found{0}, auth_failures{0};
        std::atomic<uint64_t> udp_fragments{0}, udp_retx{0}, udp_sim_drops{0}, corrupted{0};
    };

    DataServer(ChunkStore& store, Config cfg);
    ~DataServer();
    void start();
    void stop();
    uint16_t tcp_port() const { return tcp_port_; }
    uint16_t udp_port() const { return udp_.port(); }
    std::string stats_json() const;
    Stats stats;

private:
    struct UdpTransfer {
        Address to;
        uint64_t reqid = 0;
        Bytes data;
        size_t nfrag = 0;
        std::vector<uint8_t> acked;
        std::vector<uint64_t> last_sent;
        size_t acked_count = 0;
        uint64_t created = 0;
        uint32_t rounds = 0;
    };

    void tcp_accept_loop();
    void tcp_connection(Fd fd);
    void udp_loop();
    void udp_timer_loop();
    void handle_udp(const uint8_t* data, size_t n, const Address& from);
    void send_fragment(UdpTransfer& t, size_t idx, bool retx);
    void emit_datagram(const Address& to, Bytes dgram);
    void tcp_reply(const std::shared_ptr<SecureChannel>& ch, const std::shared_ptr<std::atomic<uint64_t>>& last_due, Msg type, Bytes payload);
    void maybe_corrupt(Bytes& data);

    ChunkStore& store_;
    Config cfg_;
    Bytes udp_key_;
    SharedRng rng_;
    Pacer pacer_;
    Fd tcp_listen_;
    uint16_t tcp_port_ = 0;
    UdpSocket udp_;
    std::atomic<bool> stop_{false};
    bool started_ = false;
    std::thread tcp_thread_, udp_thread_, timer_thread_;
    ThreadSet conn_threads_;
    std::mutex chan_mu_;
    std::map<SecureChannel*, std::shared_ptr<SecureChannel>> channels_;
    std::mutex tmu_;
    std::map<std::string, UdpTransfer> transfers_;
    std::unique_ptr<DelayLine> delay_;
};

}
