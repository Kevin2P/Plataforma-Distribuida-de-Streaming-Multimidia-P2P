#include "downloader.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <unistd.h>

#include <cerrno>
#include <thread>

#include "util.hpp"

namespace sp {
namespace {

uint64_t mix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

uint64_t id_hash(const std::string& id) {
    Digest d = sha256(reinterpret_cast<const uint8_t*>(id.data()), id.size());
    uint64_t h = 0;
    for (int i = 0; i < 8; i++) h = h << 8 | d[static_cast<size_t>(i)];
    return h;
}

bool write_all(int fd, const uint8_t* p, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = ::write(fd, p + done, n - done);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        done += static_cast<size_t>(r);
    }
    return true;
}

std::string num(double v) {
    char buf[48];
    std::snprintf(buf, sizeof buf, "%.3f", v);
    return buf;
}

double percentile(std::vector<double> v, double p) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t i = static_cast<size_t>(std::ceil(p * static_cast<double>(v.size()))) - 1;
    return v[std::min(i, v.size() - 1)];
}

}

std::string GetResult::to_json() const {
    std::string j = "{\"ok\":" + std::string(ok ? "true" : "false") + ",\"error\":\"" + json_escape(error) + "\",\"transport\":\"" + transport + "\"";
    j += ",\"bytes\":" + std::to_string(bytes) + ",\"streamed_bytes\":" + std::to_string(streamed_bytes) + ",\"chunks\":" + std::to_string(chunks) + ",\"resumed\":" + std::to_string(resumed);
    j += ",\"time_ms\":" + num(time_ms) + ",\"download_ms\":" + num(download_ms) + ",\"startup_ms\":" + num(startup_ms);
    j += ",\"stalls\":" + std::to_string(stalls) + ",\"stall_ms\":" + num(stall_ms);
    j += ",\"lat_avg_ms\":" + num(lat_avg_ms) + ",\"lat_p50_ms\":" + num(lat_p50_ms) + ",\"lat_p95_ms\":" + num(lat_p95_ms) +
         ",\"lat_max_ms\":" + num(lat_max_ms) + ",\"jitter_ms\":" + num(jitter_ms) + ",\"throughput_kbps\":" + num(throughput_kbps);
    j += ",\"retries\":" + std::to_string(retries) + ",\"hash_failures\":" + std::to_string(hash_failures) +
         ",\"peer_failures\":" + std::to_string(peer_failures) + ",\"request_retx\":" + std::to_string(request_retx);
    j += ",\"bytes_by_peer\":{";
    bool first = true;
    for (const auto& kv : bytes_by_peer) {
        if (!first) j += ",";
        first = false;
        j += "\"" + json_escape(kv.first) + "\":" + std::to_string(kv.second);
    }
    return j + "}}";
}

Downloader::Downloader(ChunkStore& store, TrackerClient& tracker, Bytes psk, std::string self_id, GetOptions opt)
    : store_(store), tracker_(tracker), psk_(std::move(psk)), udp_key_(udp_key(psk_)), self_id_(std::move(self_id)), opt_(std::move(opt)) {}

size_t Downloader::window() const {
    int w = std::max(opt_.window, opt_.pace ? opt_.prebuffer : opt_.workers * 4);
    return static_cast<size_t>(w);
}

void Downloader::merge_peers(const LookupReply& lr) {
    std::lock_guard<std::mutex> lock(mu_);
    std::map<std::string, bool> present;
    for (const PeerInfo& p : lr.peers) {
        if (p.id == self_id_) continue;
        present[p.id] = true;
        PeerState& ps = peers_[p.id];
        if (ps.idhash == 0) ps.idhash = id_hash(p.id);
        ps.info = p;
        size_t have_n = p.have.count();
        ps.partial = have_n > 0 && have_n < p.have.size();
    }
    for (auto it = peers_.begin(); it != peers_.end();) {
        if (!present.count(it->first) && it->second.inflight == 0) it = peers_.erase(it);
        else ++it;
    }
    cv_.notify_all();
}

bool Downloader::claim(size_t& idx, PeerInfo& peer) {
    std::lock_guard<std::mutex> lock(mu_);
    uint64_t now = now_ms();
    size_t base = opt_.pace ? play_pos_ : first_missing_;
    size_t end = std::min(m_.chunks(), base + window());
    PeerState* best_peer = nullptr;
    size_t best_idx = 0;
    double best_key = 1e18;
    for (size_t i = first_missing_; i < end; i++) {
        if (state_[i] != 0 || now < not_before_[i]) continue;
        PeerState* chosen = nullptr;
        double chosen_score = 1e18;
        int holders = 0;
        int leecher_holds = 0;
        for (auto& kv : peers_) {
            PeerState& p = kv.second;
            if (!p.info.have.get(i)) continue;
            holders++;
            if (p.partial) leecher_holds++;
            if (now < p.cooldown_until || p.inflight >= opt_.max_inflight_per_peer) continue;
            double score = p.inflight * 1000.0 + p.ewma_ms + rng_.unit() * 5.0;
            if (score < chosen_score) {
                chosen = &p;
                chosen_score = score;
            }
        }
        if (!chosen) continue;
        double key;
        if (opt_.order == Order::Strict || (opt_.pace && i < first_missing_ + 2)) key = static_cast<double>(i);
        else if (opt_.order == Order::Rarest) key = 1e6 + holders * 1e4 + rng_.unit() * 1e3;
        else if (leecher_holds > 0) key = 1e6 + static_cast<double>((i - first_missing_ + salt_) % window());
        else {
            uint64_t mine = mix64(static_cast<uint64_t>(i) ^ self_hash_);
            bool owner = true;
            for (const auto& kv : peers_)
                if (kv.second.partial && mix64(static_cast<uint64_t>(i) ^ kv.second.idhash) < mine) owner = false;
            key = 2e6 + (owner ? 0.0 : 1e5) + static_cast<double>((i - first_missing_ + salt_) % window());
        }
        if (key < best_key) {
            best_key = key;
            best_idx = i;
            best_peer = chosen;
        }
    }
    if (!best_peer) return false;
    state_[best_idx] = 1;
    best_peer->inflight++;
    idx = best_idx;
    peer = best_peer->info;
    return true;
}

void Downloader::finish(size_t idx, const PeerInfo& peer, bool fetched, bool valid, size_t nbytes, double latency_ms) {
    std::lock_guard<std::mutex> lock(mu_);
    uint64_t now = now_ms();
    auto it = peers_.find(peer.id);
    PeerState* ps = it == peers_.end() ? nullptr : &it->second;
    if (ps) ps->inflight--;
    if (fetched && valid) {
        state_[idx] = 2;
        have_count_++;
        while (first_missing_ < m_.chunks() && state_[first_missing_] == 2) first_missing_++;
        latencies_.push_back(latency_ms);
        net_bytes_ += nbytes;
        if (counter_) *counter_ += nbytes;
        if (ps) {
            ps->bytes += nbytes;
            bytes_by_peer_[peer.id] += nbytes;
            ps->ewma_ms = 0.7 * ps->ewma_ms + 0.3 * latency_ms;
            ps->fail_streak = 0;
        }
        if (have_count_ == m_.chunks()) download_done_ms_ = static_cast<double>(now - t0_);
    } else {
        state_[idx] = 0;
        retries_++;
        peer_failures_++;
        if (fetched && !valid) hash_failures_++;
        not_before_[idx] = now + 20;
        if (ps) {
            ps->fail_streak++;
            ps->cooldown_until = now + std::min<uint64_t>(200ull << std::min(ps->fail_streak - 1, 4), 3000);
        }
    }
    cv_.notify_all();
}

bool Downloader::fetch_tcp(Worker& w, const PeerInfo& peer, size_t idx, Bytes& out) {
    auto it = w.conns.find(peer.id);
    if (it == w.conns.end()) {
        auto ch = std::make_shared<SecureChannel>(connect_tcp(Endpoint{peer.host, peer.tcp_port}, 1000));
        ch->handshake_client(psk_, self_id_, kRoleData, 2000);
        it = w.conns.emplace(peer.id, ch).first;
    }
    auto& ch = it->second;
    ch->send(Msg::ChunkReq, encode_chunk_req(cid_, static_cast<uint32_t>(idx)));
    Frame f;
    if (!ch->recv(f, static_cast<int>(opt_.fetch_timeout_ms))) throw NetError("tempo esgotado esperando o chunk");
    if (f.type == static_cast<uint8_t>(Msg::ChunkErr)) {
        if (f.payload.size() != 1) throw DecodeError("CHUNK_ERR malformado");
        return false;
    }
    if (f.type != static_cast<uint8_t>(Msg::ChunkData)) throw NetError("resposta inesperada");
    uint32_t got = 0;
    decode_chunk_data(f.payload, got, out);
    if (got != idx) throw NetError("chunk de outro indice");
    return true;
}

bool Downloader::fetch_udp(Worker& w, const PeerInfo& peer, size_t idx, Bytes& out) {
    if (!w.udp.valid()) w.udp = UdpSocket::open(0);
    std::string akey = peer.id + ":" + std::to_string(peer.udp_port);
    auto ait = w.addrs.find(akey);
    if (ait == w.addrs.end()) {
        Address a;
        if (!Address::resolve(Endpoint{peer.host, peer.udp_port}, SOCK_DGRAM, a)) throw NetError("nao foi possivel resolver o peer");
        ait = w.addrs.emplace(akey, a).first;
    }
    const Address to = ait->second;
    uint64_t reqid = w.rng.next();
    uint32_t want_len = m_.chunk_len(idx);
    ByteWriter rq;
    rq.raw(cid_.data(), 32);
    rq.u32(static_cast<uint32_t>(idx));
    Bytes req = udp_seal(udp_key_, UMsg::Req, reqid, rq.bytes());
    auto send_client = [&](const Bytes& dg) {
        if (opt_.client_profile.loss > 0 && w.rng.unit() < opt_.client_profile.loss) return;
        w.udp.send_to(to, dg.data(), dg.size());
    };
    send_client(req);
    size_t nfrag = 0, got_count = 0;
    std::vector<uint8_t> got;
    Bytes buf;
    auto send_ack = [&]() {
        size_t nb = (nfrag + 7) / 8;
        Bytes bits(nb, 0);
        for (size_t i = 0; i < nfrag; i++)
            if (got[i]) bits[i / 8] = static_cast<uint8_t>(bits[i / 8] | (1u << (i % 8)));
        ByteWriter a;
        a.u8(static_cast<uint8_t>(nb));
        a.raw(bits);
        send_client(udp_seal(udp_key_, UMsg::Ack, reqid, a.bytes()));
    };
    uint64_t deadline = now_ms() + opt_.fetch_timeout_ms;
    uint8_t dg[2048];
    Address from;
    while (now_ms() < deadline) {
        int wait = static_cast<int>(std::min<uint64_t>(opt_.rto_ms, deadline - now_ms()));
        int n = w.udp.recv_from(dg, sizeof dg, from, wait);
        if (n < 0) {
            if (nfrag == 0) {
                request_retx_++;
                send_client(req);
            } else {
                send_ack();
            }
            continue;
        }
        UMsg type;
        uint64_t rid;
        Bytes body;
        if (!udp_open(udp_key_, dg, static_cast<size_t>(n), type, rid, body) || rid != reqid) continue;
        if (type == UMsg::Err) {
            if (body.size() == 1) return false;
            continue;
        }
        if (type != UMsg::Data) continue;
        try {
            ByteReader r(body);
            uint16_t fi = r.u16();
            uint16_t ft = r.u16();
            uint32_t clen = r.u32();
            Bytes payload = r.raw(r.remaining());
            if (clen != want_len || ft == 0 || ft != (clen + kUdpFragment - 1) / kUdpFragment || fi >= ft) continue;
            size_t expect = (fi + 1u < ft) ? kUdpFragment : clen - kUdpFragment * (ft - 1u);
            if (payload.size() != expect) continue;
            if (nfrag == 0) {
                nfrag = ft;
                got.assign(nfrag, 0);
                buf.assign(clen, 0);
            } else if (ft != nfrag) {
                continue;
            }
            if (!got[fi]) {
                std::memcpy(buf.data() + static_cast<size_t>(fi) * kUdpFragment, payload.data(), payload.size());
                got[fi] = 1;
                got_count++;
            }
            send_ack();
            if (got_count == nfrag) {
                send_ack();
                out = std::move(buf);
                return true;
            }
        } catch (const DecodeError&) {
        }
    }
    return false;
}

void Downloader::worker_main(int wid) {
    Worker w(0x9E37 + static_cast<uint64_t>(wid) * 7919);
    while (!done_) {
        size_t idx = 0;
        PeerInfo peer;
        if (!claim(idx, peer)) {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait_for(lock, std::chrono::milliseconds(20));
            continue;
        }
        uint64_t t0 = now_ms();
        Bytes data;
        bool fetched = false;
        try {
            fetched = opt_.transport == Transport::Tcp ? fetch_tcp(w, peer, idx, data) : fetch_udp(w, peer, idx, data);
        } catch (const std::exception& e) {
            LOG_DEBUG("get", "falha ao buscar o chunk %zu de %s: %s", idx, peer.id.c_str(), e.what());
            w.conns.erase(peer.id);
            fetched = false;
        }
        bool valid = fetched && store_.put(cid_, static_cast<uint32_t>(idx), data);
        finish(idx, peer, fetched, valid, data.size(), static_cast<double>(now_ms() - t0));
    }
}

void Downloader::refresher() {
    while (!done_) {
        LookupReply lr;
        if (tracker_.lookup(cid_, lr)) merge_peers(lr);
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait_for(lock, std::chrono::milliseconds(200), [this] { return done_.load(); });
    }
}

bool Downloader::play(GetResult& res, uint64_t deadline) {
    std::unique_lock<std::mutex> lock(mu_);
    size_t n = m_.chunks();
    size_t need = std::min<size_t>(static_cast<size_t>(std::max(opt_.prebuffer, 1)), n);
    while (first_missing_ < need) {
        if (now_ms() > deadline) return false;
        cv_.wait_for(lock, std::chrono::milliseconds(20));
    }
    res.startup_ms = static_cast<double>(now_ms() - t0_);
    double clock = static_cast<double>(now_ms());
    for (size_t i = 0; i < n; i++) {
        if (opt_.pace) {
            while (static_cast<double>(now_ms()) < clock) {
                if (now_ms() > deadline) return false;
                cv_.wait_for(lock, std::chrono::milliseconds(std::max<int64_t>(1, static_cast<int64_t>(clock - static_cast<double>(now_ms())))));
            }
        }
        if (state_[i] != 2) {
            uint64_t s0 = now_ms();
            size_t target = std::min(n, i + need);
            while (first_missing_ < target) {
                if (now_ms() > deadline) return false;
                cv_.wait_for(lock, std::chrono::milliseconds(20));
            }
            res.stalls++;
            res.stall_ms += static_cast<double>(now_ms() - s0);
            clock = static_cast<double>(now_ms());
        }
        if (opt_.stream_fd >= 0 && !stream_closed_) {
            lock.unlock();
            Bytes data;
            bool ok = store_.get(cid_, static_cast<uint32_t>(i), data) && write_all(opt_.stream_fd, data.data(), data.size());
            lock.lock();
            if (ok) res.streamed_bytes += data.size();
            else stream_closed_ = true;
        }
        clock += opt_.pace ? m_.chunk_duration_ms(i) : 0.0;
        play_pos_ = i + 1;
        cv_.notify_all();
    }
    return true;
}

GetResult Downloader::run(const Digest& id) {
    GetResult res;
    res.transport = opt_.transport == Transport::Tcp ? "tcp" : "udp";
    cid_ = id;
    t0_ = now_ms();
    uint64_t deadline = t0_ + opt_.total_timeout_ms;
    LookupReply lr;
    bool found = false;
    while (now_ms() < deadline) {
        if (tracker_.wait_connected(200) && tracker_.lookup(cid_, lr)) {
            found = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!found) {
        res.error = "conteudo nao encontrado no tracker";
        return res;
    }
    if (lr.manifest.id() != cid_) {
        res.error = "o manifesto recebido nao corresponde ao identificador pedido";
        return res;
    }
    m_ = lr.manifest;
    store_.add_manifest(m_);
    self_hash_ = id_hash(self_id_);
    rng_ = Rng(self_hash_ ^ 0x5EEDull);
    salt_ = static_cast<size_t>(self_hash_ >> 40) % window();
    Bitmap have = store_.bitmap(cid_);
    size_t n = m_.chunks();
    state_.assign(n, 0);
    not_before_.assign(n, 0);
    for (size_t i = 0; i < n; i++) {
        if (have.get(i)) {
            state_[i] = 2;
            have_count_++;
        }
    }
    res.resumed = have_count_;
    while (first_missing_ < n && state_[first_missing_] == 2) first_missing_++;
    if (have_count_ == n) download_done_ms_ = 0;
    merge_peers(lr);

    std::vector<std::thread> threads;
    for (int i = 0; i < std::max(opt_.workers, 1); i++) threads.emplace_back([this, i] { worker_main(i); });
    threads.emplace_back([this] { refresher(); });
    bool played = play(res, deadline);
    done_ = true;
    cv_.notify_all();
    for (auto& t : threads) t.join();

    res.time_ms = static_cast<double>(now_ms() - t0_);
    res.chunks = n;
    res.ok = played && have_count_ == n;
    if (!res.ok) res.error = "tempo esgotado ou conteudo incompleto";
    res.bytes = m_.size;
    {
        std::lock_guard<std::mutex> lock(mu_);
        res.retries = retries_;
        res.hash_failures = hash_failures_;
        res.peer_failures = peer_failures_;
        res.request_retx = request_retx_.load();
        res.download_ms = download_done_ms_ >= 0 ? download_done_ms_ : res.time_ms;
        if (!latencies_.empty()) {
            double sum = 0;
            for (double v : latencies_) sum += v;
            res.lat_avg_ms = sum / static_cast<double>(latencies_.size());
            double var = 0;
            for (double v : latencies_) var += (v - res.lat_avg_ms) * (v - res.lat_avg_ms);
            res.jitter_ms = std::sqrt(var / static_cast<double>(latencies_.size()));
            res.lat_p50_ms = percentile(latencies_, 0.50);
            res.lat_p95_ms = percentile(latencies_, 0.95);
            res.lat_max_ms = *std::max_element(latencies_.begin(), latencies_.end());
        }
        if (res.download_ms > 0) res.throughput_kbps = static_cast<double>(net_bytes_) * 8.0 / res.download_ms;
        res.bytes_by_peer = bytes_by_peer_;
    }
    if (res.ok && !opt_.out_path.empty() && !store_.assemble(cid_, opt_.out_path)) {
        res.ok = false;
        res.error = "falha ao gravar o arquivo de saida";
    }
    return res;
}

}
