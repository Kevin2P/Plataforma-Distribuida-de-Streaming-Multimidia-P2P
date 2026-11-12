#include "tracker_client.hpp"

#include <algorithm>

#include "util.hpp"

namespace sp {

TrackerClient::TrackerClient(Config cfg, ChunkStore& store, Counters counters)
    : cfg_(std::move(cfg)), store_(store), counters_(std::move(counters)) {}

TrackerClient::~TrackerClient() { stop(); }

void TrackerClient::start() { thread_ = std::thread([this] { loop(); }); }

void TrackerClient::stop() {
    if (stop_.exchange(true)) return;
    wake_cv_.notify_all();
    {
        std::lock_guard<std::mutex> lock(io_mu_);
        if (chan_) {
            try {
                chan_->send(Msg::Bye, Bytes());
            } catch (const std::exception&) {
            }
            chan_->shutdown();
        }
    }
    if (thread_.joinable()) thread_.join();
}

bool TrackerClient::interruptible_sleep(uint32_t ms) {
    std::unique_lock<std::mutex> lock(wake_mu_);
    wake_cv_.wait_for(lock, std::chrono::milliseconds(ms), [this] { return stop_.load() || broken_.load(); });
    return !stop_.load();
}

bool TrackerClient::wait_connected(int timeout_ms) {
    uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms);
    while (now_ms() < deadline) {
        if (connected()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return connected();
}

void TrackerClient::loop() {
    uint32_t backoff = 200;
    while (!stop_) {
        try {
            auto ch = std::make_shared<SecureChannel>(connect_tcp(cfg_.tracker, 1500));
            ch->handshake_client(cfg_.psk, cfg_.id, kRoleTracker, 3000);
            run_session(ch);
            backoff = 200;
        } catch (const AuthError& e) {
            LOG_INFO("peer", "tracker recusou a autenticacao: %s", e.what());
        } catch (const std::exception& e) {
            LOG_DEBUG("peer", "sessao com o tracker caiu: %s", e.what());
        }
        {
            std::lock_guard<std::mutex> lock(io_mu_);
            chan_.reset();
        }
        connected_ = false;
        broken_ = false;
        if (stop_) break;
        interruptible_sleep(backoff);
        backoff = std::min<uint32_t>(backoff * 2, 2000);
    }
}

void TrackerClient::run_session(const std::shared_ptr<SecureChannel>& ch) {
    ch->send(Msg::Register, encode_register(cfg_.tcp_port, cfg_.udp_port));
    Frame f;
    if (!ch->recv(f, 3000)) throw NetError("tracker nao respondeu ao registro");
    if (f.type == static_cast<uint8_t>(Msg::Error)) throw AuthError("registro recusado: " + decode_text(f.payload));
    if (f.type != static_cast<uint8_t>(Msg::RegisterOk)) throw NetError("resposta inesperada ao registro");
    ByteReader r(f.payload);
    uint32_t interval = std::min<uint32_t>(r.u32(), cfg_.max_heartbeat_ms);
    if (interval < 50) interval = 50;
    {
        std::lock_guard<std::mutex> lock(io_mu_);
        chan_ = ch;
    }
    broken_ = false;
    connected_ = true;
    sessions_++;
    LOG_INFO("peer", "registrado no tracker (heartbeat a cada %u ms)", interval);
    if (cfg_.share)
        for (const Digest& id : store_.contents()) publish_content(id);
    while (!stop_ && !broken_) {
        interruptible_sleep(interval);
        if (stop_ || broken_) break;
        heartbeat(ch);
    }
}

bool TrackerClient::rpc(Msg type, const Bytes& payload, Frame& reply, int timeout_ms) {
    std::lock_guard<std::mutex> lock(io_mu_);
    if (!chan_) return false;
    try {
        chan_->send(type, payload);
        if (!chan_->recv(reply, timeout_ms)) throw NetError("tempo esgotado esperando o tracker");
        return reply.type != static_cast<uint8_t>(Msg::Error);
    } catch (const std::exception& e) {
        LOG_DEBUG("peer", "falha na chamada ao tracker: %s", e.what());
        broken_ = true;
        wake_cv_.notify_all();
        return false;
    }
}

void TrackerClient::publish_content(const Digest& id) {
    Manifest m;
    if (!store_.manifest(id, m)) return;
    Bitmap have = store_.bitmap(id);
    if (have.count() == 0) return;
    ByteWriter w;
    w.raw(m.encode());
    w.blob(have.bytes());
    Frame reply;
    rpc(Msg::Publish, w.bytes(), reply, 3000);
}

void TrackerClient::heartbeat(const std::shared_ptr<SecureChannel>&) {
    HeartbeatMsg hb;
    counters_(hb.uploaded, hb.downloaded);
    for (const Digest& id : cfg_.share ? store_.contents() : std::vector<Digest>()) {
        Bitmap have = store_.bitmap(id);
        if (have.count() == 0 || hb.holds.size() >= kMaxHoldings) continue;
        hb.holds.push_back(Holding{id, have.bytes()});
    }
    Frame reply;
    if (!rpc(Msg::Heartbeat, encode_heartbeat(hb), reply, 3000)) return;
    try {
        for (const Digest& id : decode_digests(reply.payload)) publish_content(id);
    } catch (const DecodeError&) {
    }
}

bool TrackerClient::lookup(const Digest& id, LookupReply& out) {
    Frame reply;
    if (!rpc(Msg::Lookup, encode_digest(id), reply, 3000)) return false;
    try {
        out = decode_lookup_reply(reply.payload);
        return true;
    } catch (const DecodeError&) {
        return false;
    }
}

bool TrackerClient::list(std::vector<ContentSummary>& out) {
    Frame reply;
    if (!rpc(Msg::List, Bytes(), reply, 3000)) return false;
    try {
        out = decode_list_reply(reply.payload);
        return true;
    } catch (const DecodeError&) {
        return false;
    }
}

}
