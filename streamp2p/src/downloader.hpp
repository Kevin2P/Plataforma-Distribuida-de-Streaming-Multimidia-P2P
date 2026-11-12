#pragma once
#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "emulation.hpp"
#include "protocol.hpp"
#include "store.hpp"
#include "tracker_client.hpp"

namespace sp {

enum class Transport { Tcp, Udp };
enum class Order { Strict, Rarest, Cheap };

struct GetOptions {
    Transport transport = Transport::Tcp;
    int workers = 4;
    int window = 64;
    Order order = Order::Cheap;
    int prebuffer = 3;
    bool pace = true;
    int max_inflight_per_peer = 2;
    uint32_t fetch_timeout_ms = 2000;
    uint32_t total_timeout_ms = 120000;
    uint32_t rto_ms = 100;
    LinkProfile client_profile;
    std::string out_path;
    int stream_fd = -1;
};

struct GetResult {
    bool ok = false;
    std::string error;
    std::string transport;
    uint64_t bytes = 0;
    uint64_t streamed_bytes = 0;
    size_t chunks = 0;
    size_t resumed = 0;
    double time_ms = 0;
    double download_ms = 0;
    double startup_ms = 0;
    uint32_t stalls = 0;
    double stall_ms = 0;
    double lat_avg_ms = 0, lat_p50_ms = 0, lat_p95_ms = 0, lat_max_ms = 0, jitter_ms = 0;
    double throughput_kbps = 0;
    uint64_t retries = 0, hash_failures = 0, peer_failures = 0, request_retx = 0;
    std::map<std::string, uint64_t> bytes_by_peer;
    std::string to_json() const;
};

class Downloader {
public:
    Downloader(ChunkStore& store, TrackerClient& tracker, Bytes psk, std::string self_id, GetOptions opt);
    GetResult run(const Digest& id);
    void set_downloaded_counter(std::atomic<uint64_t>* counter) { counter_ = counter; }

private:
    struct PeerState {
        PeerInfo info;
        int inflight = 0;
        int fail_streak = 0;
        uint64_t cooldown_until = 0;
        double ewma_ms = 30.0;
        uint64_t bytes = 0;
        uint64_t idhash = 0;
        bool partial = false;
    };
    struct Worker {
        std::map<std::string, std::shared_ptr<SecureChannel>> conns;
        UdpSocket udp;
        std::map<std::string, Address> addrs;
        Rng rng;
        explicit Worker(uint64_t seed) : rng(seed) {}
    };

    size_t window() const;
    void merge_peers(const LookupReply& lr);
    bool claim(size_t& idx, PeerInfo& peer);
    void finish(size_t idx, const PeerInfo& peer, bool fetched, bool valid, size_t nbytes, double latency_ms);
    void worker_main(int wid);
    void refresher();
    bool fetch_tcp(Worker& w, const PeerInfo& peer, size_t idx, Bytes& out);
    bool fetch_udp(Worker& w, const PeerInfo& peer, size_t idx, Bytes& out);
    bool play(GetResult& res, uint64_t deadline);

    ChunkStore& store_;
    TrackerClient& tracker_;
    Bytes psk_, udp_key_;
    std::string self_id_;
    GetOptions opt_;
    Digest cid_{};
    Manifest m_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<uint8_t> state_;
    std::vector<uint64_t> not_before_;
    size_t first_missing_ = 0;
    size_t play_pos_ = 0;
    bool stream_closed_ = false;
    size_t salt_ = 0;
    uint64_t self_hash_ = 0;
    size_t have_count_ = 0;
    std::map<std::string, PeerState> peers_;
    std::atomic<bool> done_{false};
    std::vector<double> latencies_;
    uint64_t retries_ = 0, hash_failures_ = 0, peer_failures_ = 0, net_bytes_ = 0;
    std::atomic<uint64_t> request_retx_{0};
    std::atomic<uint64_t>* counter_ = nullptr;
    std::map<std::string, uint64_t> bytes_by_peer_;
    double download_done_ms_ = -1;
    uint64_t t0_ = 0;
    Rng rng_{7};
};

}
