#include "protocol.hpp"

#include <cstring>

#include "util.hpp"

namespace sp {
namespace {

const int kFrameBodyTimeoutMs = 10000;
const int kSendTimeoutMs = 10000;

Bytes label_bytes(const char* label) {
    return Bytes(reinterpret_cast<const uint8_t*>(label), reinterpret_cast<const uint8_t*>(label) + std::strlen(label));
}

Digest proof(const Bytes& psk, const char* label, const Bytes& n1, const Bytes& n2, const std::string& id) {
    Hmac h(psk);
    h.update(label_bytes(label));
    h.update(n1);
    h.update(n2);
    h.update(reinterpret_cast<const uint8_t*>(id.data()), id.size());
    return h.finish();
}

}

Digest SecureChannel::mac_of(uint8_t dir, uint64_t ctr, const uint8_t* header, const Bytes& payload) const {
    Hmac h(key_);
    uint8_t prefix[9];
    prefix[0] = dir;
    for (int i = 0; i < 8; i++) prefix[1 + i] = static_cast<uint8_t>(ctr >> (56 - 8 * i));
    h.update(prefix, sizeof prefix);
    h.update(header, kHeaderSize);
    h.update(payload);
    return h.finish();
}

void SecureChannel::write_frame(uint8_t type, const Bytes& payload, bool with_mac) {
    if (payload.size() > kMaxFramePayload) throw NetError("mensagem grande demais");
    uint8_t header[kHeaderSize] = {'S', 'P', kVersion, type, 0, 0, 0, 0};
    uint32_t len = static_cast<uint32_t>(payload.size());
    for (int i = 0; i < 4; i++) header[4 + i] = static_cast<uint8_t>(len >> (24 - 8 * i));
    Bytes out;
    out.reserve(kHeaderSize + payload.size() + kMacSize);
    out.insert(out.end(), header, header + kHeaderSize);
    out.insert(out.end(), payload.begin(), payload.end());
    std::lock_guard<std::mutex> lock(send_mu_);
    if (with_mac) {
        Digest m = mac_of(client_ ? 0 : 1, send_ctr_, header, payload);
        out.insert(out.end(), m.begin(), m.end());
        send_ctr_++;
    }
    send_all(fd_.get(), out.data(), out.size(), kSendTimeoutMs);
    sent_ += out.size();
}

// Le um quadro. Fora do handshake, wait_ms e a espera pelo primeiro byte e o resto do quadro tem
// ate kFrameBodyTimeoutMs. No handshake, wait_ms e o prazo do quadro inteiro (o prazo da etapa),
// para que quem envia meio cabecalho e para nao prenda a thread alem dele, e o payload e limitado
// a kMaxHandshakePayload.
bool SecureChannel::read_frame(Frame& out, bool expect_mac, int wait_ms, bool handshake) {
    uint64_t deadline = now_ms() + static_cast<uint64_t>(wait_ms < 0 ? 0 : wait_ms);
    auto body_wait = [&]() -> int {
        if (!handshake) return kFrameBodyTimeoutMs;
        uint64_t now = now_ms();
        return now >= deadline ? 1 : static_cast<int>(deadline - now);
    };
    if (!wait_readable(fd_.get(), wait_ms)) return false;
    uint8_t header[kHeaderSize];
    recv_exact(fd_.get(), header, kHeaderSize, body_wait());
    if (header[0] != 'S' || header[1] != 'P' || header[2] != kVersion) throw AuthError("cabecalho de quadro invalido");
    uint32_t len = 0;
    for (int i = 0; i < 4; i++) len = len << 8 | header[4 + i];
    if (len > (handshake ? kMaxHandshakePayload : kMaxFramePayload)) throw AuthError("mensagem grande demais");
    Bytes payload(len);
    if (len > 0) recv_exact(fd_.get(), payload.data(), len, body_wait());
    if (expect_mac) {
        uint8_t mac[kMacSize];
        recv_exact(fd_.get(), mac, kMacSize, body_wait());
        Digest want = mac_of(client_ ? 1 : 0, recv_ctr_, header, payload);
        if (!ct_equal(want.data(), mac, kMacSize)) throw AuthError("MAC invalido: mensagem adulterada, repetida ou fora de ordem");
        recv_ctr_++;
        received_ += kHeaderSize + len + kMacSize;
    } else {
        received_ += kHeaderSize + len;
    }
    out.type = header[3];
    out.payload = std::move(payload);
    return true;
}

void SecureChannel::send(Msg type, const Bytes& payload) {
    if (!secured_) throw AuthError("canal ainda nao autenticado");
    write_frame(static_cast<uint8_t>(type), payload, true);
}

bool SecureChannel::recv(Frame& out, int idle_timeout_ms) {
    if (!secured_) throw AuthError("canal ainda nao autenticado");
    return read_frame(out, true, idle_timeout_ms);
}

void SecureChannel::handshake_client(const Bytes& psk, const std::string& id, uint8_t role, int timeout_ms) {
    client_ = true;
    Bytes nc = random_bytes(16);
    ByteWriter hello;
    hello.raw(nc);
    hello.str(id);
    hello.u8(role);
    write_frame(static_cast<uint8_t>(Msg::Hello), hello.bytes(), false);

    Frame f;
    if (!read_frame(f, false, timeout_ms, true)) throw NetError("tempo esgotado no handshake");
    if (f.type == static_cast<uint8_t>(Msg::Error)) throw AuthError("recusado: " + decode_text(f.payload));
    if (f.type != static_cast<uint8_t>(Msg::Challenge)) throw AuthError("resposta inesperada no handshake");
    ByteReader r(f.payload);
    Bytes ns = r.raw(16);
    Digest server_proof;
    r.raw_into(server_proof.data(), 32);
    r.expect_end();
    Digest want = proof(psk, "SPv1-server", nc, ns, id);
    if (!ct_equal(want.data(), server_proof.data(), 32)) throw AuthError("o servidor nao provou conhecer a chave");

    Digest cp = proof(psk, "SPv1-client", ns, nc, id);
    write_frame(static_cast<uint8_t>(Msg::Auth), Bytes(cp.begin(), cp.end()), false);
    Digest k = proof(psk, "SPv1-session", nc, ns, id);
    key_.assign(k.begin(), k.end());
    secured_ = true;

    Frame ok;
    if (!read_frame(ok, true, timeout_ms, true)) throw NetError("tempo esgotado no handshake");
    if (ok.type != static_cast<uint8_t>(Msg::AuthOk)) throw AuthError("autenticacao recusada");
}

void SecureChannel::handshake_server(const Bytes& psk, int timeout_ms, std::string& id_out, uint8_t& role_out) {
    client_ = false;
    Frame f;
    if (!read_frame(f, false, timeout_ms, true)) throw NetError("tempo esgotado no handshake");
    if (f.type != static_cast<uint8_t>(Msg::Hello)) throw AuthError("esperava HELLO");
    Bytes nc;
    std::string id;
    uint8_t role;
    try {
        ByteReader r(f.payload);
        nc = r.raw(16);
        id = r.str();
        role = r.u8();
        r.expect_end();
    } catch (const DecodeError&) {
        throw AuthError("HELLO malformado");
    }
    if (!valid_id(id)) {
        write_frame(static_cast<uint8_t>(Msg::Error), encode_text("identificador invalido"), false);
        throw AuthError("identificador invalido");
    }
    Bytes ns = random_bytes(16);
    Digest sp_ = proof(psk, "SPv1-server", nc, ns, id);
    ByteWriter ch;
    ch.raw(ns);
    ch.raw(sp_.data(), sp_.size());
    write_frame(static_cast<uint8_t>(Msg::Challenge), ch.bytes(), false);

    Frame a;
    try {
        if (!read_frame(a, false, timeout_ms, true)) throw AuthError("cliente nao concluiu o handshake (tempo esgotado)");
    } catch (const NetError&) {
        throw AuthError("cliente abandonou o handshake de " + id);
    }
    Digest want = proof(psk, "SPv1-client", ns, nc, id);
    if (a.type != static_cast<uint8_t>(Msg::Auth) || a.payload.size() != 32 || !ct_equal(want.data(), a.payload.data(), 32)) {
        write_frame(static_cast<uint8_t>(Msg::Error), encode_text("autenticacao falhou"), false);
        throw AuthError("autenticacao falhou para " + id);
    }
    Digest k = proof(psk, "SPv1-session", nc, ns, id);
    key_.assign(k.begin(), k.end());
    secured_ = true;
    write_frame(static_cast<uint8_t>(Msg::AuthOk), Bytes(), true);
    id_out = id;
    role_out = role;
}

Bytes encode_register(uint16_t tcp_port, uint16_t udp_port) {
    ByteWriter w;
    w.u16(tcp_port);
    w.u16(udp_port);
    return w.take();
}

void decode_register(const Bytes& b, uint16_t& tcp_port, uint16_t& udp_port) {
    ByteReader r(b);
    tcp_port = r.u16();
    udp_port = r.u16();
    r.expect_end();
}

Bytes encode_heartbeat(const HeartbeatMsg& m) {
    ByteWriter w;
    w.u64(m.uploaded);
    w.u64(m.downloaded);
    w.u16(static_cast<uint16_t>(m.holds.size()));
    for (const Holding& h : m.holds) {
        w.raw(h.content.data(), 32);
        w.blob(h.bitmap);
    }
    return w.take();
}

HeartbeatMsg decode_heartbeat(const Bytes& b) {
    ByteReader r(b);
    HeartbeatMsg m;
    m.uploaded = r.u64();
    m.downloaded = r.u64();
    size_t n = r.u16();
    if (n > kMaxHoldings) throw DecodeError("anuncios demais");
    for (size_t i = 0; i < n; i++) {
        Holding h;
        r.raw_into(h.content.data(), 32);
        h.bitmap = r.blob(kMaxChunks / 8 + 1);
        m.holds.push_back(std::move(h));
    }
    r.expect_end();
    return m;
}

Bytes encode_digests(const std::vector<Digest>& v) {
    ByteWriter w;
    w.u16(static_cast<uint16_t>(v.size()));
    for (const Digest& d : v) w.raw(d.data(), 32);
    return w.take();
}

std::vector<Digest> decode_digests(const Bytes& b) {
    ByteReader r(b);
    size_t n = r.u16();
    if (n > kMaxHoldings) throw DecodeError("lista longa demais");
    std::vector<Digest> v(n);
    for (size_t i = 0; i < n; i++) r.raw_into(v[i].data(), 32);
    r.expect_end();
    return v;
}

Bytes encode_digest(const Digest& d) { return Bytes(d.begin(), d.end()); }

Digest decode_digest(const Bytes& b) {
    if (b.size() != 32) throw DecodeError("identificador invalido");
    Digest d;
    std::memcpy(d.data(), b.data(), 32);
    return d;
}

Bytes encode_lookup_reply(const LookupReply& lr) {
    ByteWriter w;
    w.raw(lr.manifest.encode());
    w.u16(static_cast<uint16_t>(lr.peers.size()));
    for (const PeerInfo& p : lr.peers) {
        w.str(p.id);
        w.str(p.host);
        w.u16(p.tcp_port);
        w.u16(p.udp_port);
        w.blob(p.have.bytes());
    }
    return w.take();
}

LookupReply decode_lookup_reply(const Bytes& b) {
    ByteReader r(b);
    LookupReply lr;
    lr.manifest = Manifest::decode(r);
    size_t n = r.u16();
    if (n > kMaxPeersInReply) throw DecodeError("peers demais");
    for (size_t i = 0; i < n; i++) {
        PeerInfo p;
        p.id = r.str();
        p.host = r.str();
        p.tcp_port = r.u16();
        p.udp_port = r.u16();
        Bytes raw = r.blob(kMaxChunks / 8 + 1);
        if (!valid_id(p.id) || !Bitmap::from_bytes(raw, lr.manifest.chunks(), p.have)) throw DecodeError("peer invalido");
        lr.peers.push_back(std::move(p));
    }
    r.expect_end();
    return lr;
}

Bytes encode_list_reply(const std::vector<ContentSummary>& v) {
    ByteWriter w;
    w.u16(static_cast<uint16_t>(v.size()));
    for (const ContentSummary& c : v) {
        w.raw(c.id.data(), 32);
        w.str(c.name);
        w.u64(c.size);
        w.u32(c.chunk_size);
        w.u32(c.bitrate_kbps);
        w.u32(c.chunks);
        w.u32(c.seeders);
        w.u32(c.holders);
    }
    return w.take();
}

std::vector<ContentSummary> decode_list_reply(const Bytes& b) {
    ByteReader r(b);
    size_t n = r.u16();
    if (n > kMaxListEntries) throw DecodeError("lista longa demais");
    std::vector<ContentSummary> v;
    for (size_t i = 0; i < n; i++) {
        ContentSummary c;
        r.raw_into(c.id.data(), 32);
        c.name = r.str();
        c.size = r.u64();
        c.chunk_size = r.u32();
        c.bitrate_kbps = r.u32();
        c.chunks = r.u32();
        c.seeders = r.u32();
        c.holders = r.u32();
        if (!valid_name(c.name)) throw DecodeError("nome invalido");
        v.push_back(std::move(c));
    }
    r.expect_end();
    return v;
}

Bytes encode_chunk_req(const Digest& content, uint32_t index) {
    ByteWriter w;
    w.raw(content.data(), 32);
    w.u32(index);
    return w.take();
}

void decode_chunk_req(const Bytes& b, Digest& content, uint32_t& index) {
    ByteReader r(b);
    r.raw_into(content.data(), 32);
    index = r.u32();
    r.expect_end();
}

Bytes encode_chunk_data(uint32_t index, const Bytes& data) {
    ByteWriter w;
    w.u32(index);
    w.blob(data);
    return w.take();
}

void decode_chunk_data(const Bytes& b, uint32_t& index, Bytes& data) {
    ByteReader r(b);
    index = r.u32();
    data = r.blob(kMaxChunkSize);
    r.expect_end();
}

Bytes encode_text(const std::string& s) {
    ByteWriter w;
    w.str(s.size() > 200 ? s.substr(0, 200) : s);
    return w.take();
}

std::string decode_text(const Bytes& b) {
    try {
        ByteReader r(b);
        return r.str();
    } catch (const DecodeError&) {
        return "?";
    }
}

Bytes udp_key(const Bytes& psk) {
    const char label[] = "SPv1-udp";
    Digest d = hmac_sha256(psk, reinterpret_cast<const uint8_t*>(label), sizeof label - 1);
    return Bytes(d.begin(), d.end());
}

Bytes udp_seal(const Bytes& key, UMsg type, uint64_t reqid, const Bytes& body) {
    ByteWriter w;
    w.u8('S');
    w.u8('U');
    w.u8(kVersion);
    w.u8(static_cast<uint8_t>(type));
    w.u64(reqid);
    w.raw(body);
    Digest m = hmac_sha256(key, w.bytes());
    w.raw(m.data(), kUdpMacSize);
    return w.take();
}

bool udp_open(const Bytes& key, const uint8_t* data, size_t n, UMsg& type, uint64_t& reqid, Bytes& body) {
    if (n < 12 + kUdpMacSize || n > kUdpMaxDatagram) return false;
    if (data[0] != 'S' || data[1] != 'U' || data[2] != kVersion) return false;
    Digest m = hmac_sha256(key, data, n - kUdpMacSize);
    if (!ct_equal(m.data(), data + n - kUdpMacSize, kUdpMacSize)) return false;
    if (data[3] < 1 || data[3] > 4) return false;
    type = static_cast<UMsg>(data[3]);
    ByteReader r(data + 4, 8);
    reqid = r.u64();
    body.assign(data + 12, data + n - kUdpMacSize);
    return true;
}

}
