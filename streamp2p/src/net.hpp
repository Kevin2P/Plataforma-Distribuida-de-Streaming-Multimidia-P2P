#pragma once
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <stdexcept>
#include <string>

#include "bytes.hpp"

namespace sp {

struct NetError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class Fd {
public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    Fd(Fd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Fd& operator=(Fd&& o) noexcept {
        if (this != &o) {
            reset();
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { reset(); }
    int get() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
    void reset(int fd = -1);
    int release();

private:
    int fd_ = -1;
};

struct Endpoint {
    std::string host;
    uint16_t port = 0;
    std::string str() const;
};

bool parse_endpoint(const std::string& text, Endpoint& out);

class Address {
public:
    Address();
    static bool resolve(const Endpoint& ep, int socktype, Address& out);
    static Address from_sockaddr(const sockaddr* sa, socklen_t len);
    const sockaddr* sa() const { return reinterpret_cast<const sockaddr*>(&ss_); }
    socklen_t len() const { return len_; }
    int family() const { return ss_.ss_family; }
    std::string host() const;
    uint16_t port() const;
    std::string key() const;
    Address mapped_v6() const;

private:
    sockaddr_storage ss_;
    socklen_t len_;
};

Fd listen_tcp(uint16_t port, uint16_t* bound_port);
Fd accept_tcp(int listen_fd, int timeout_ms, std::string* peer_host);
Fd connect_tcp(const Endpoint& ep, int timeout_ms);
bool wait_readable(int fd, int timeout_ms);
void send_all(int fd, const uint8_t* data, size_t n, int timeout_ms);
void recv_exact(int fd, uint8_t* data, size_t n, int timeout_ms);
void shutdown_socket(int fd);

class UdpSocket {
public:
    UdpSocket() = default;
    static UdpSocket open(uint16_t port);
    bool send_to(const Address& to, const uint8_t* data, size_t n) const;
    int recv_from(uint8_t* buf, size_t cap, Address& from, int timeout_ms) const;
    uint16_t port() const { return port_; }
    int fd() const { return fd_.get(); }
    bool valid() const { return fd_.valid(); }

private:
    Fd fd_;
    int family_ = AF_INET;
    uint16_t port_ = 0;
};

}
