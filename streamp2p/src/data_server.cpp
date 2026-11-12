#include "data_server.hpp"

#include <algorithm>

namespace sp {
namespace {
const size_t kMaxTransfers = 512;
}

DataServer::DataServer(ChunkStore& store, Config cfg)
    : store_(store), cfg_(std::move(cfg)), udp_key_(udp_key(cfg_.psk)), rng_(cfg_.profile.seed), pacer_(cfg_.profile.rate_bps) {}

DataServer::~DataServer() { stop(); }

void DataServer::start() {
    tcp_listen_ = listen_tcp(cfg_.tcp_port, &tcp_port_);
    udp_ = UdpSocket::open(cfg_.udp_port);
    if (cfg_.profile.shapes()) delay_ = std::make_unique<DelayLine>();
    started_ = true;
    tcp_thread_ = std::thread([this] { tcp_accept_loop(); });
    udp_thread_ = std::thread([this] { udp_loop(); });
    timer_thread_ = std::thread([this] { udp_timer_loop(); });
}

void DataServer::stop() {
    if (!started_ || stop_.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lock(chan_mu_);
        for (auto& kv : channels_) kv.second->shutdown();
    }
    if (tcp_thread_.joinable()) tcp_thread_.join();
    if (udp_thread_.joinable()) udp_thread_.join();
    if (timer_thread_.joinable()) timer_thread_.join();
    conn_threads_.join_all();
    delay_.reset();
}

std::string DataServer::stats_json() const {
    return "{\"uploaded_bytes\":" + std::to_string(stats.uploaded_bytes.load()) + ",\"chunks_served\":" + std::to_string(stats.chunks_served.load()) +
           ",\"requests\":" + std::to_string(stats.requests.load()) + ",\"not_found\":" + std::to_string(stats.not_found.load()) +
           ",\"auth_failures\":" + std::to_string(stats.auth_failures.load()) + ",\"udp_fragments\":" + std::to_string(stats.udp_fragments.load()) +
           ",\"udp_retx\":" + std::to_string(stats.udp_retx.load()) + ",\"udp_sim_drops\":" + std::to_string(stats.udp_sim_drops.load()) +
           ",\"corrupted\":" + std::to_string(stats.corrupted.load()) + "}";
}

void DataServer::maybe_corrupt(Bytes& data) {
    if (cfg_.profile.corrupt > 0 && !data.empty() && rng_.unit() < cfg_.profile.corrupt) {
        data[rng_.below(static_cast<uint32_t>(data.size()))] ^= 0x5a;
        stats.corrupted++;
    }
}

void DataServer::tcp_accept_loop() {
    while (!stop_) {
        Fd fd = accept_tcp(tcp_listen_.get(), 100, nullptr);
        if (!fd.valid()) continue;
        if (conn_threads_.running() >= 256) continue;
        auto holder = std::make_shared<Fd>(std::move(fd));
        conn_threads_.spawn([this, holder] { tcp_connection(std::move(*holder)); });
    }
}

void DataServer::tcp_reply(const std::shared_ptr<SecureChannel>& ch, const std::shared_ptr<std::atomic<uint64_t>>& last_due, Msg type, Bytes payload) {
    if (!delay_) {
        ch->send(type, payload);
        return;
    }
    uint64_t now = now_ms();
    uint64_t due = now + cfg_.profile.delay_ms + (cfg_.profile.jitter_ms ? rng_.below(cfg_.profile.jitter_ms + 1) : 0);
    due = std::max(due, pacer_.reserve(payload.size() + kHeaderSize + kMacSize, now));
    due = std::max(due, last_due->load());
    last_due->store(due);
    delay_->schedule(due, [ch, type, payload = std::move(payload)] {
        try {
            ch->send(type, payload);
        } catch (const std::exception&) {
        }
    });
}

void DataServer::tcp_connection(Fd fd) {
    auto ch = std::make_shared<SecureChannel>(std::move(fd));
    std::string peer;
    uint8_t role = 0;
    try {
        ch->handshake_server(cfg_.psk, 3000, peer, role);
    } catch (const AuthError& e) {
        stats.auth_failures++;
        LOG_DEBUG("dados", "autenticacao recusada: %s", e.what());
        return;
    } catch (const std::exception&) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(chan_mu_);
        channels_[ch.get()] = ch;
    }
    auto last_due = std::make_shared<std::atomic<uint64_t>>(0);
    try {
        if (role != kRoleData) {
            ch->send(Msg::Error, encode_text("esta porta atende apenas sessoes de dados"));
        } else {
            uint64_t idle = now_ms() + 60000;
            Frame f;
            while (!stop_) {
                if (!ch->recv(f, 300)) {
                    if (now_ms() > idle) break;
                    continue;
                }
                idle = now_ms() + 60000;
                if (f.type == static_cast<uint8_t>(Msg::ChunkReq)) {
                    Digest cid;
                    uint32_t idx;
                    decode_chunk_req(f.payload, cid, idx);
                    stats.requests++;
                    Bytes data;
                    if (!store_.get(cid, idx, data)) {
                        stats.not_found++;
                        ByteWriter w;
                        w.u8(1);
                        tcp_reply(ch, last_due, Msg::ChunkErr, w.take());
                    } else {
                        maybe_corrupt(data);
                        uint64_t n = data.size();
                        tcp_reply(ch, last_due, Msg::ChunkData, encode_chunk_data(idx, data));
                        stats.chunks_served++;
                        stats.uploaded_bytes += n;
                    }
                } else {
                    break;
                }
            }
        }
    } catch (const std::exception& e) {
        LOG_DEBUG("dados", "conexao de %s encerrada: %s", peer.c_str(), e.what());
    }
    std::lock_guard<std::mutex> lock(chan_mu_);
    channels_.erase(ch.get());
}

void DataServer::emit_datagram(const Address& to, Bytes dgram) {
    if (cfg_.profile.loss > 0 && rng_.unit() < cfg_.profile.loss) {
        stats.udp_sim_drops++;
        return;
    }
    if (!delay_) {
        udp_.send_to(to, dgram.data(), dgram.size());
        return;
    }
    uint64_t now = now_ms();
    uint64_t due = now + cfg_.profile.delay_ms + (cfg_.profile.jitter_ms ? rng_.below(cfg_.profile.jitter_ms + 1) : 0);
    due = std::max(due, pacer_.reserve(dgram.size() + 28, now));
    delay_->schedule(due, [this, to, dgram = std::move(dgram)] { udp_.send_to(to, dgram.data(), dgram.size()); });
}

void DataServer::send_fragment(UdpTransfer& t, size_t idx, bool retx) {
    size_t off = idx * kUdpFragment;
    size_t len = std::min(kUdpFragment, t.data.size() - off);
    ByteWriter w;
    w.u16(static_cast<uint16_t>(idx));
    w.u16(static_cast<uint16_t>(t.nfrag));
    w.u32(static_cast<uint32_t>(t.data.size()));
    w.raw(t.data.data() + off, len);
    t.last_sent[idx] = now_ms();
    stats.udp_fragments++;
    if (retx) stats.udp_retx++;
    emit_datagram(t.to, udp_seal(udp_key_, UMsg::Data, t.reqid, w.bytes()));
}

void DataServer::udp_loop() {
    uint8_t buf[2048];
    Address from;
    while (!stop_) {
        int n = udp_.recv_from(buf, sizeof buf, from, 100);
        if (n <= 0) continue;
        try {
            handle_udp(buf, static_cast<size_t>(n), from);
        } catch (const std::exception&) {
        }
    }
}

void DataServer::handle_udp(const uint8_t* data, size_t n, const Address& from) {
    UMsg type;
    uint64_t reqid;
    Bytes body;
    if (!udp_open(udp_key_, data, n, type, reqid, body)) return;
    std::string key = from.key() + "#" + std::to_string(reqid);
    if (type == UMsg::Req) {
        ByteReader r(body);
        Digest cid;
        r.raw_into(cid.data(), 32);
        uint32_t idx = r.u32();
        r.expect_end();
        {
            std::lock_guard<std::mutex> lock(tmu_);
            if (transfers_.count(key)) return;
            if (transfers_.size() >= kMaxTransfers) {
                emit_datagram(from, udp_seal(udp_key_, UMsg::Err, reqid, Bytes{2}));
                return;
            }
        }
        stats.requests++;
        Bytes chunk;
        if (!store_.get(cid, idx, chunk)) {
            stats.not_found++;
            emit_datagram(from, udp_seal(udp_key_, UMsg::Err, reqid, Bytes{1}));
            return;
        }
        maybe_corrupt(chunk);
        UdpTransfer t;
        t.to = from;
        t.reqid = reqid;
        t.data = std::move(chunk);
        t.nfrag = (t.data.size() + kUdpFragment - 1) / kUdpFragment;
        if (t.nfrag == 0 || t.nfrag > 0xFFFF) return;
        t.acked.assign(t.nfrag, 0);
        t.last_sent.assign(t.nfrag, 0);
        t.created = now_ms();
        std::lock_guard<std::mutex> lock(tmu_);
        auto res = transfers_.emplace(key, std::move(t));
        if (!res.second) return;
        for (size_t i = 0; i < res.first->second.nfrag; i++) send_fragment(res.first->second, i, false);
    } else if (type == UMsg::Ack) {
        ByteReader r(body);
        size_t nbytes = r.u8();
        Bytes bits = r.raw(nbytes);
        r.expect_end();
        std::lock_guard<std::mutex> lock(tmu_);
        auto it = transfers_.find(key);
        if (it == transfers_.end()) return;
        UdpTransfer& t = it->second;
        size_t highest = 0;
        bool any = false;
        for (size_t i = 0; i < t.nfrag && i / 8 < bits.size(); i++) {
            if ((bits[i / 8] >> (i % 8)) & 1) {
                if (!t.acked[i]) {
                    t.acked[i] = 1;
                    t.acked_count++;
                }
                highest = i;
                any = true;
            }
        }
        if (t.acked_count == t.nfrag) {
            stats.chunks_served++;
            stats.uploaded_bytes += t.data.size();
            transfers_.erase(it);
            return;
        }
        if (any) {
            uint64_t now = now_ms();
            for (size_t i = 0; i < highest; i++)
                if (!t.acked[i] && now - t.last_sent[i] >= cfg_.udp_rto_ms / 2) send_fragment(t, i, true);
        }
    }
}

void DataServer::udp_timer_loop() {
    while (!stop_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        uint64_t now = now_ms();
        std::lock_guard<std::mutex> lock(tmu_);
        for (auto it = transfers_.begin(); it != transfers_.end();) {
            UdpTransfer& t = it->second;
            if (now - t.created > 20000 || t.rounds > 25) {
                it = transfers_.erase(it);
                continue;
            }
            uint64_t rto = static_cast<uint64_t>(cfg_.udp_rto_ms) << std::min<uint32_t>(t.rounds, 3);
            bool resent = false;
            for (size_t i = 0; i < t.nfrag; i++) {
                if (!t.acked[i] && now - t.last_sent[i] >= rto) {
                    send_fragment(t, i, true);
                    resent = true;
                }
            }
            if (resent) t.rounds++;
            ++it;
        }
    }
}

}
