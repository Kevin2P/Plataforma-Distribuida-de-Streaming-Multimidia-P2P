#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "bytes.hpp"
#include "manifest.hpp"
#include "net.hpp"
#include "sha256.hpp"

namespace sp {

constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderSize = 8;
constexpr size_t kMacSize = 32;
constexpr size_t kMaxFramePayload = 4u << 20;
// HELLO, CHALLENGE, AUTH e o ERROR do handshake cabem com folga neste limite. Ele vale antes da
// autenticacao, para que quem nao tem a chave nao faca o servidor reservar 4 MiB por conexao.
constexpr size_t kMaxHandshakePayload = 256;
constexpr uint8_t kRoleTracker = 0;
constexpr uint8_t kRoleData = 1;

enum class Msg : uint8_t {
    Hello = 1,
    Challenge = 2,
    Auth = 3,
    AuthOk = 4,
    Error = 5,
    Register = 10,
    RegisterOk = 11,
    Publish = 12,
    PublishOk = 13,
    Heartbeat = 14,
    HeartbeatOk = 15,
    List = 16,
    ListReply = 17,
    Lookup = 18,
    LookupReply = 19,
    Bye = 20,
    ChunkReq = 30,
    ChunkData = 31,
    ChunkErr = 32
};

struct AuthError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Frame {
    uint8_t type = 0;
    Bytes payload;
};

class SecureChannel {
public:
    explicit SecureChannel(Fd fd) : fd_(std::move(fd)) {}
    void handshake_client(const Bytes& psk, const std::string& id, uint8_t role, int timeout_ms);
    void handshake_server(const Bytes& psk, int timeout_ms, std::string& id_out, uint8_t& role_out);
    void send(Msg type, const Bytes& payload);
    bool recv(Frame& out, int idle_timeout_ms);
    int fd() const { return fd_.get(); }
    void shutdown() { shutdown_socket(fd_.get()); }
    uint64_t bytes_sent() const { return sent_.load(); }
    uint64_t bytes_received() const { return received_.load(); }

private:
    void write_frame(uint8_t type, const Bytes& payload, bool with_mac);
    bool read_frame(Frame& out, bool expect_mac, int wait_ms, bool handshake = false);
    Digest mac_of(uint8_t dir, uint64_t ctr, const uint8_t* header, const Bytes& payload) const;

    Fd fd_;
    Bytes key_;
    bool secured_ = false;
    bool client_ = false;
    uint64_t send_ctr_ = 0;
    uint64_t recv_ctr_ = 0;
    std::mutex send_mu_;
    std::atomic<uint64_t> sent_{0};
    std::atomic<uint64_t> received_{0};
};

struct PeerInfo {
    std::string id;
    std::string host;
    uint16_t tcp_port = 0;
    uint16_t udp_port = 0;
    Bitmap have;
};

struct LookupReply {
    Manifest manifest;
    std::vector<PeerInfo> peers;
};

struct ContentSummary {
    Digest id{};
    std::string name;
    uint64_t size = 0;
    uint32_t chunk_size = 0;
    uint32_t bitrate_kbps = 0;
    uint32_t chunks = 0;
    uint32_t seeders = 0;
    uint32_t holders = 0;
};

struct Holding {
    Digest content;
    Bytes bitmap;
};

struct HeartbeatMsg {
    uint64_t uploaded = 0;
    uint64_t downloaded = 0;
    std::vector<Holding> holds;
};

constexpr size_t kMaxHoldings = 256;
constexpr size_t kMaxListEntries = 1024;
constexpr size_t kMaxPeersInReply = 512;

Bytes encode_register(uint16_t tcp_port, uint16_t udp_port);
void decode_register(const Bytes& b, uint16_t& tcp_port, uint16_t& udp_port);
Bytes encode_heartbeat(const HeartbeatMsg& m);
HeartbeatMsg decode_heartbeat(const Bytes& b);
Bytes encode_digests(const std::vector<Digest>& v);
std::vector<Digest> decode_digests(const Bytes& b);
Bytes encode_digest(const Digest& d);
Digest decode_digest(const Bytes& b);
Bytes encode_lookup_reply(const LookupReply& r);
LookupReply decode_lookup_reply(const Bytes& b);
Bytes encode_list_reply(const std::vector<ContentSummary>& v);
std::vector<ContentSummary> decode_list_reply(const Bytes& b);
Bytes encode_chunk_req(const Digest& content, uint32_t index);
void decode_chunk_req(const Bytes& b, Digest& content, uint32_t& index);
Bytes encode_chunk_data(uint32_t index, const Bytes& data);
void decode_chunk_data(const Bytes& b, uint32_t& index, Bytes& data);
Bytes encode_text(const std::string& s);
std::string decode_text(const Bytes& b);

enum class UMsg : uint8_t { Req = 1, Data = 2, Ack = 3, Err = 4 };
constexpr size_t kUdpFragment = 1200;
constexpr size_t kUdpMacSize = 16;
constexpr size_t kUdpMaxDatagram = 1500;

Bytes udp_key(const Bytes& psk);
Bytes udp_seal(const Bytes& key, UMsg type, uint64_t reqid, const Bytes& body);
bool udp_open(const Bytes& key, const uint8_t* data, size_t n, UMsg& type, uint64_t& reqid, Bytes& body);

}
