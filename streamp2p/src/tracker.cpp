#include "tracker.hpp"

#include <algorithm>

namespace sp {

void TrackerState::event_locked(const std::string& text) {
    events_.push_back(Event{wall_ms(), text});
    while (events_.size() > 100) events_.pop_front();
}

void TrackerState::gc_contents_locked() {
    for (auto it = contents_.begin(); it != contents_.end();) {
        bool held = false;
        for (const auto& kv : peers_) {
            auto h = kv.second.holds.find(it->first);
            if (h != kv.second.holds.end() && h->second.count() > 0) {
                held = true;
                break;
            }
        }
        if (held) {
            ++it;
        } else {
            event_locked("conteúdo removido (sem peers): " + it->second.name);
            it = contents_.erase(it);
        }
    }
}

void TrackerState::remove_locked(uint64_t session, const std::string& reason) {
    auto it = peers_.find(session);
    if (it == peers_.end()) return;
    auto idit = by_id_.find(it->second.id);
    if (idit != by_id_.end() && idit->second == session) by_id_.erase(idit);
    event_locked("peer " + it->second.id + " saiu: " + reason);
    peers_.erase(it);
    gc_contents_locked();
}

uint64_t TrackerState::register_peer(const std::string& id, const std::string& host, uint16_t tcp, uint16_t udp, uint64_t now) {
    std::lock_guard<std::mutex> lock(mu_);
    auto existing = by_id_.find(id);
    if (existing == by_id_.end() && peers_.size() >= kMaxPeers) return 0;
    if (existing != by_id_.end()) {
        stats_.replaced++;
        remove_locked(existing->second, "substituído por novo registro");
    }
    Peer p;
    p.session = ++next_session_;
    p.id = id;
    p.host = host;
    p.tcp = tcp;
    p.udp = udp;
    p.joined = p.last_seen = now;
    by_id_[id] = p.session;
    peers_[p.session] = p;
    stats_.registrations++;
    event_locked("peer " + id + " entrou (" + host + ", tcp " + std::to_string(tcp) + ", udp " + std::to_string(udp) + ")");
    return p.session;
}

bool TrackerState::is_active(uint64_t session) const {
    std::lock_guard<std::mutex> lock(mu_);
    return peers_.count(session) > 0;
}

bool TrackerState::publish(uint64_t session, const Manifest& m, const Bytes& bitmap, uint64_t now) {
    if (!m.valid()) return false;
    Bitmap bm;
    if (!Bitmap::from_bytes(bitmap, m.chunks(), bm)) return false;
    std::string key = to_hex(m.id());
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(session);
    if (it == peers_.end()) return false;
    if (!contents_.count(key)) {
        if (contents_.size() >= kMaxContents) return false;
        contents_[key] = m;
        event_locked("novo conteúdo publicado por " + it->second.id + ": " + m.name);
    }
    it->second.holds[key] = bm;
    it->second.last_seen = now;
    stats_.publishes++;
    return true;
}

bool TrackerState::heartbeat(uint64_t session, const HeartbeatMsg& hb, uint64_t now, std::vector<Digest>& unknown) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(session);
    if (it == peers_.end()) return false;
    Peer& p = it->second;
    p.last_seen = now;
    p.up = hb.uploaded;
    p.down = hb.downloaded;
    std::map<std::string, Bitmap> next;
    for (const Holding& h : hb.holds) {
        std::string key = to_hex(h.content);
        auto c = contents_.find(key);
        if (c == contents_.end()) {
            unknown.push_back(h.content);
            continue;
        }
        Bitmap bm;
        if (Bitmap::from_bytes(h.bitmap, c->second.chunks(), bm)) next[key] = bm;
    }
    p.holds = std::move(next);
    stats_.heartbeats++;
    gc_contents_locked();
    return true;
}

bool TrackerState::lookup(uint64_t session, const Digest& id, LookupReply& out) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!peers_.count(session)) return false;
    stats_.lookups++;
    std::string key = to_hex(id);
    auto c = contents_.find(key);
    if (c == contents_.end()) return false;
    out.manifest = c->second;
    out.peers.clear();
    std::vector<const Peer*> list;
    for (const auto& kv : peers_) {
        if (kv.first == session) continue;
        auto h = kv.second.holds.find(key);
        if (h != kv.second.holds.end() && h->second.count() > 0) list.push_back(&kv.second);
    }
    std::sort(list.begin(), list.end(), [](const Peer* a, const Peer* b) { return a->id < b->id; });
    for (const Peer* p : list) {
        if (out.peers.size() >= kMaxPeersInReply) break;
        out.peers.push_back(PeerInfo{p->id, p->host, p->tcp, p->udp, p->holds.at(key)});
    }
    return true;
}

std::vector<ContentSummary> TrackerState::list() {
    std::lock_guard<std::mutex> lock(mu_);
    stats_.lists++;
    std::vector<ContentSummary> out;
    for (const auto& kv : contents_) {
        ContentSummary s;
        s.id = kv.second.id();
        s.name = kv.second.name;
        s.size = kv.second.size;
        s.chunk_size = kv.second.chunk_size;
        s.bitrate_kbps = kv.second.bitrate_kbps;
        s.chunks = static_cast<uint32_t>(kv.second.chunks());
        for (const auto& pk : peers_) {
            auto h = pk.second.holds.find(kv.first);
            if (h == pk.second.holds.end()) continue;
            if (h->second.count() > 0) s.holders++;
            if (h->second.full()) s.seeders++;
        }
        out.push_back(std::move(s));
    }
    return out;
}

void TrackerState::remove(uint64_t session, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mu_);
    if (peers_.count(session)) stats_.disconnects++;
    remove_locked(session, reason);
}

size_t TrackerState::expire(uint64_t now) {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<uint64_t> dead;
    for (const auto& kv : peers_)
        if (now - kv.second.last_seen > ttl_ms_) dead.push_back(kv.first);
    for (uint64_t s : dead) {
        stats_.expired++;
        remove_locked(s, "sem heartbeat há mais de " + std::to_string(ttl_ms_) + " ms");
    }
    return dead.size();
}

void TrackerState::note_auth_failure(const std::string& host) {
    std::lock_guard<std::mutex> lock(mu_);
    stats_.auth_failures++;
    event_locked("autenticação recusada de " + host);
}

void TrackerState::note_protocol_error(const std::string& who) {
    std::lock_guard<std::mutex> lock(mu_);
    stats_.protocol_errors++;
    event_locked("mensagem inválida de " + who);
}

TrackerStats TrackerState::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

size_t TrackerState::peer_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return peers_.size();
}

size_t TrackerState::content_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return contents_.size();
}

std::string TrackerState::status_json(uint64_t now) const {
    std::lock_guard<std::mutex> lock(mu_);
    std::string j = "{";
    j += "\"server_time_ms\":" + std::to_string(wall_ms());
    j += ",\"uptime_ms\":" + std::to_string(now - started_mono_);
    j += ",\"ttl_ms\":" + std::to_string(ttl_ms_);
    j += ",\"stats\":{\"registrations\":" + std::to_string(stats_.registrations) + ",\"replaced\":" + std::to_string(stats_.replaced) +
         ",\"publishes\":" + std::to_string(stats_.publishes) + ",\"heartbeats\":" + std::to_string(stats_.heartbeats) +
         ",\"lookups\":" + std::to_string(stats_.lookups) + ",\"expired\":" + std::to_string(stats_.expired) +
         ",\"disconnects\":" + std::to_string(stats_.disconnects) + ",\"auth_failures\":" + std::to_string(stats_.auth_failures) +
         ",\"protocol_errors\":" + std::to_string(stats_.protocol_errors) + "}";
    j += ",\"peers\":[";
    bool first = true;
    for (const auto& kv : peers_) {
        const Peer& p = kv.second;
        if (!first) j += ",";
        first = false;
        j += "{\"id\":\"" + json_escape(p.id) + "\",\"host\":\"" + json_escape(p.host) + "\",\"tcp_port\":" + std::to_string(p.tcp) +
             ",\"udp_port\":" + std::to_string(p.udp) + ",\"age_ms\":" + std::to_string(now - p.last_seen) +
             ",\"uptime_ms\":" + std::to_string(now - p.joined) + ",\"uploaded\":" + std::to_string(p.up) +
             ",\"downloaded\":" + std::to_string(p.down) + ",\"contents\":[";
        bool f2 = true;
        for (const auto& h : p.holds) {
            if (!f2) j += ",";
            f2 = false;
            j += "{\"id\":\"" + h.first + "\",\"have\":" + std::to_string(h.second.count()) + ",\"total\":" + std::to_string(h.second.size()) + "}";
        }
        j += "]}";
    }
    j += "],\"contents\":[";
    first = true;
    for (const auto& kv : contents_) {
        const Manifest& m = kv.second;
        size_t n = m.chunks();
        std::vector<uint32_t> count(n, 0);
        uint32_t seeders = 0, holders = 0;
        for (const auto& pk : peers_) {
            auto h = pk.second.holds.find(kv.first);
            if (h == pk.second.holds.end()) continue;
            if (h->second.count() > 0) holders++;
            if (h->second.full()) seeders++;
            for (size_t i = 0; i < n; i++)
                if (h->second.get(i)) count[i]++;
        }
        size_t bucket = (n + 1023) / 1024;
        if (!first) j += ",";
        first = false;
        j += "{\"id\":\"" + kv.first + "\",\"name\":\"" + json_escape(m.name) + "\",\"size\":" + std::to_string(m.size) +
             ",\"chunk_size\":" + std::to_string(m.chunk_size) + ",\"bitrate_kbps\":" + std::to_string(m.bitrate_kbps) +
             ",\"chunks\":" + std::to_string(n) + ",\"seeders\":" + std::to_string(seeders) + ",\"holders\":" + std::to_string(holders) +
             ",\"availability\":[";
        for (size_t i = 0; i < n; i += bucket) {
            uint32_t lo = count[i];
            for (size_t k = i; k < std::min(n, i + bucket); k++) lo = std::min(lo, count[k]);
            if (i) j += ",";
            j += std::to_string(lo);
        }
        j += "]}";
    }
    j += "],\"events\":[";
    first = true;
    for (const Event& e : events_) {
        if (!first) j += ",";
        first = false;
        j += "{\"t\":" + std::to_string(e.wall) + ",\"msg\":\"" + json_escape(e.text) + "\"}";
    }
    j += "]}";
    return j;
}

Tracker::Tracker(Config cfg) : cfg_(std::move(cfg)), state_(cfg_.ttl_ms) {}

Tracker::~Tracker() { stop(); }

void Tracker::start() {
    listen_ = listen_tcp(cfg_.port, &port_);
    if (cfg_.web_port >= 0) {
        http_ = std::make_unique<HttpServer>(static_cast<uint16_t>(cfg_.web_port), [this] { return state_.status_json(now_ms()); });
        http_->start();
    }
    acceptor_ = std::thread([this] { accept_loop(); });
    reaper_ = std::thread([this] { reaper_loop(); });
    LOG_INFO("tracker", "escutando na porta TCP %u (ttl %llu ms)", port_, static_cast<unsigned long long>(cfg_.ttl_ms));
}

void Tracker::stop() {
    if (stop_.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lock(conns_mu_);
        for (auto& kv : conns_) kv.second->shutdown();
    }
    if (acceptor_.joinable()) acceptor_.join();
    if (reaper_.joinable()) reaper_.join();
    if (http_) http_->stop();
    threads_.join_all();
}

void Tracker::accept_loop() {
    while (!stop_) {
        std::string host;
        Fd fd = accept_tcp(listen_.get(), 100, &host);
        if (!fd.valid()) continue;
        if (threads_.running() >= kMaxPeers + 64) continue;
        auto holder = std::make_shared<Fd>(std::move(fd));
        threads_.spawn([this, holder, host] { serve(std::move(*holder), host); });
    }
}

void Tracker::reaper_loop() {
    while (!stop_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        size_t n = state_.expire(now_ms());
        if (n > 0) LOG_INFO("tracker", "%zu peer(s) expirado(s) por falta de heartbeat", n);
    }
}

void Tracker::serve(Fd fd, std::string host) {
    auto ch = std::make_shared<SecureChannel>(std::move(fd));
    std::string id;
    uint8_t role = 0;
    try {
        ch->handshake_server(cfg_.psk, 3000, id, role);
    } catch (const AuthError& e) {
        state_.note_auth_failure(host);
        LOG_INFO("tracker", "autenticacao recusada de %s: %s", host.c_str(), e.what());
        return;
    } catch (const std::exception&) {
        return;
    }
    uint64_t session = 0;
    uint64_t first_deadline = now_ms() + 5000;
    try {
        if (role != kRoleTracker) {
            ch->send(Msg::Error, encode_text("esta porta atende apenas sessoes de controle"));
            return;
        }
        Frame f;
        while (!stop_) {
            if (!ch->recv(f, 300)) {
                if (session && !state_.is_active(session)) break;
                if (!session && now_ms() > first_deadline) break;
                continue;
            }
            Msg type = static_cast<Msg>(f.type);
            if (!session && type != Msg::Register && type != Msg::Bye) {
                ch->send(Msg::Error, encode_text("registre-se primeiro"));
                break;
            }
            if (type == Msg::Register) {
                uint16_t tcp, udp;
                decode_register(f.payload, tcp, udp);
                if (session) {
                    ch->send(Msg::Error, encode_text("ja registrado"));
                    break;
                }
                session = state_.register_peer(id, host, tcp, udp, now_ms());
                if (session == 0) {
                    ch->send(Msg::Error, encode_text("tracker lotado"));
                    break;
                }
                {
                    std::lock_guard<std::mutex> lock(conns_mu_);
                    conns_[session] = ch;
                }
                ByteWriter w;
                w.u32(static_cast<uint32_t>(cfg_.ttl_ms / 3));
                w.u32(static_cast<uint32_t>(cfg_.ttl_ms));
                ch->send(Msg::RegisterOk, w.bytes());
            } else if (type == Msg::Publish) {
                ByteReader r(f.payload);
                Manifest m = Manifest::decode(r);
                Bytes bitmap = r.blob(kMaxChunks / 8 + 1);
                r.expect_end();
                if (!state_.publish(session, m, bitmap, now_ms())) {
                    ch->send(Msg::Error, encode_text("publicacao recusada"));
                    break;
                }
                ch->send(Msg::PublishOk, Bytes());
            } else if (type == Msg::Heartbeat) {
                std::vector<Digest> unknown;
                if (!state_.heartbeat(session, decode_heartbeat(f.payload), now_ms(), unknown)) {
                    ch->send(Msg::Error, encode_text("sessao expirada"));
                    break;
                }
                ch->send(Msg::HeartbeatOk, encode_digests(unknown));
            } else if (type == Msg::List) {
                if (!f.payload.empty()) throw DecodeError("LIST com payload");
                ch->send(Msg::ListReply, encode_list_reply(state_.list()));
            } else if (type == Msg::Lookup) {
                LookupReply reply;
                if (!state_.lookup(session, decode_digest(f.payload), reply)) {
                    ch->send(Msg::Error, encode_text("conteudo desconhecido"));
                    continue;
                }
                ch->send(Msg::LookupReply, encode_lookup_reply(reply));
            } else if (type == Msg::Bye) {
                break;
            } else {
                state_.note_protocol_error(id);
                ch->send(Msg::Error, encode_text("tipo de mensagem invalido"));
                break;
            }
        }
    } catch (const DecodeError& e) {
        state_.note_protocol_error(id);
        try {
            ch->send(Msg::Error, encode_text("mensagem malformada"));
        } catch (const std::exception&) {
        }
    } catch (const AuthError& e) {
        state_.note_auth_failure(host);
        LOG_INFO("tracker", "violacao de integridade de %s (%s): %s", id.c_str(), host.c_str(), e.what());
    } catch (const std::exception&) {
    }
    if (session) {
        state_.remove(session, "conexão encerrada");
        std::lock_guard<std::mutex> lock(conns_mu_);
        conns_.erase(session);
    }
}

}
