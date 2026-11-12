#include "net.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "util.hpp"

namespace sp {
namespace {

void set_nonblocking(int fd, bool on) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
}

void tune_tcp(int fd) {
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

int poll_wait(int fd, short events, int timeout_ms) {
    uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms < 0 ? 0 : timeout_ms);
    for (;;) {
        uint64_t now = now_ms();
        int remaining = now >= deadline ? 0 : static_cast<int>(deadline - now);
        pollfd p{fd, events, 0};
        int r = ::poll(&p, 1, remaining);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) throw NetError(std::string("poll: ") + std::strerror(errno));
        return r > 0 ? p.revents : 0;
    }
}

}

void Fd::reset(int fd) {
    if (fd_ >= 0) ::close(fd_);
    fd_ = fd;
}

int Fd::release() {
    int f = fd_;
    fd_ = -1;
    return f;
}

std::string Endpoint::str() const {
    std::string p = std::to_string(port);
    return host.find(':') != std::string::npos ? "[" + host + "]:" + p : host + ":" + p;
}

bool parse_endpoint(const std::string& text, Endpoint& out) {
    std::string host, port;
    if (!text.empty() && text[0] == '[') {
        size_t close = text.find(']');
        if (close == std::string::npos || close + 1 >= text.size() || text[close + 1] != ':') return false;
        host = text.substr(1, close - 1);
        port = text.substr(close + 2);
    } else {
        size_t colon = text.rfind(':');
        if (colon == std::string::npos || text.find(':') != colon) return false;
        host = text.substr(0, colon);
        port = text.substr(colon + 1);
    }
    if (host.empty() || port.empty() || port.size() > 5) return false;
    for (char c : port)
        if (c < '0' || c > '9') return false;
    unsigned long v = std::strtoul(port.c_str(), nullptr, 10);
    if (v == 0 || v > 65535) return false;
    out.host = host;
    out.port = static_cast<uint16_t>(v);
    return true;
}

Address::Address() : len_(0) { std::memset(&ss_, 0, sizeof ss_); }

bool Address::resolve(const Endpoint& ep, int socktype, Address& out) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    addrinfo* res = nullptr;
    std::string port = std::to_string(ep.port);
    if (::getaddrinfo(ep.host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return false;
    out = from_sockaddr(res->ai_addr, res->ai_addrlen);
    ::freeaddrinfo(res);
    return true;
}

Address Address::from_sockaddr(const sockaddr* sa, socklen_t len) {
    Address a;
    if (len > sizeof(sockaddr_storage)) len = sizeof(sockaddr_storage);
    std::memcpy(&a.ss_, sa, len);
    a.len_ = len;
    return a;
}

std::string Address::host() const {
    char buf[NI_MAXHOST];
    if (::getnameinfo(sa(), len_, buf, sizeof buf, nullptr, 0, NI_NUMERICHOST) != 0) return "?";
    std::string s = buf;
    if (s.rfind("::ffff:", 0) == 0 && s.find('.') != std::string::npos) s = s.substr(7);
    return s;
}

uint16_t Address::port() const {
    if (ss_.ss_family == AF_INET) return ntohs(reinterpret_cast<const sockaddr_in*>(&ss_)->sin_port);
    if (ss_.ss_family == AF_INET6) return ntohs(reinterpret_cast<const sockaddr_in6*>(&ss_)->sin6_port);
    return 0;
}

std::string Address::key() const { return host() + "|" + std::to_string(port()); }

Address Address::mapped_v6() const {
    if (ss_.ss_family != AF_INET) return *this;
    const sockaddr_in* in4 = reinterpret_cast<const sockaddr_in*>(&ss_);
    sockaddr_in6 in6;
    std::memset(&in6, 0, sizeof in6);
    in6.sin6_family = AF_INET6;
    in6.sin6_port = in4->sin_port;
    in6.sin6_addr.s6_addr[10] = 0xff;
    in6.sin6_addr.s6_addr[11] = 0xff;
    std::memcpy(&in6.sin6_addr.s6_addr[12], &in4->sin_addr, 4);
    return from_sockaddr(reinterpret_cast<const sockaddr*>(&in6), sizeof in6);
}

Fd listen_tcp(uint16_t port, uint16_t* bound_port) {
    int family = AF_INET6;
    Fd fd(::socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!fd.valid()) {
        family = AF_INET;
        fd.reset(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    }
    if (!fd.valid()) throw NetError(std::string("socket: ") + std::strerror(errno));
    int one = 1;
    ::setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (family == AF_INET6) {
        int zero = 0;
        ::setsockopt(fd.get(), IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        sockaddr_in6 a;
        std::memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(port);
        if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&a), sizeof a) < 0)
            throw NetError("nao foi possivel abrir a porta TCP " + std::to_string(port) + ": " + std::strerror(errno));
    } else {
        sockaddr_in a;
        std::memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons(port);
        if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&a), sizeof a) < 0)
            throw NetError("nao foi possivel abrir a porta TCP " + std::to_string(port) + ": " + std::strerror(errno));
    }
    if (::listen(fd.get(), 128) < 0) throw NetError(std::string("listen: ") + std::strerror(errno));
    if (bound_port) {
        sockaddr_storage ss;
        socklen_t len = sizeof ss;
        ::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&ss), &len);
        *bound_port = Address::from_sockaddr(reinterpret_cast<sockaddr*>(&ss), len).port();
    }
    return fd;
}

Fd accept_tcp(int listen_fd, int timeout_ms, std::string* peer_host) {
    if (!(poll_wait(listen_fd, POLLIN, timeout_ms) & POLLIN)) return Fd();
    sockaddr_storage ss;
    socklen_t len = sizeof ss;
    int c = ::accept4(listen_fd, reinterpret_cast<sockaddr*>(&ss), &len, SOCK_CLOEXEC);
    if (c < 0) return Fd();
    Fd fd(c);
    tune_tcp(c);
    if (peer_host) *peer_host = Address::from_sockaddr(reinterpret_cast<sockaddr*>(&ss), len).host();
    return fd;
}

Fd connect_tcp(const Endpoint& ep, int timeout_ms) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string port = std::to_string(ep.port);
    if (::getaddrinfo(ep.host.c_str(), port.c_str(), &hints, &res) != 0 || !res)
        throw NetError("nao foi possivel resolver " + ep.str());
    std::string last_error = "sem enderecos";
    for (addrinfo* p = res; p; p = p->ai_next) {
        Fd fd(::socket(p->ai_family, p->ai_socktype | SOCK_CLOEXEC, p->ai_protocol));
        if (!fd.valid()) {
            last_error = std::strerror(errno);
            continue;
        }
        set_nonblocking(fd.get(), true);
        int r = ::connect(fd.get(), p->ai_addr, p->ai_addrlen);
        if (r < 0 && errno != EINPROGRESS) {
            last_error = std::strerror(errno);
            continue;
        }
        if (r < 0) {
            int ev = poll_wait(fd.get(), POLLOUT, timeout_ms);
            if (!(ev & (POLLOUT | POLLERR | POLLHUP))) {
                last_error = "tempo esgotado";
                continue;
            }
            int err = 0;
            socklen_t el = sizeof err;
            ::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &err, &el);
            if (err != 0) {
                last_error = std::strerror(err);
                continue;
            }
        }
        set_nonblocking(fd.get(), false);
        tune_tcp(fd.get());
        ::freeaddrinfo(res);
        return fd;
    }
    ::freeaddrinfo(res);
    throw NetError("conexao com " + ep.str() + " falhou: " + last_error);
}

bool wait_readable(int fd, int timeout_ms) {
    return (poll_wait(fd, POLLIN, timeout_ms) & (POLLIN | POLLHUP | POLLERR)) != 0;
}

void send_all(int fd, const uint8_t* data, size_t n, int timeout_ms) {
    uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms);
    size_t sent = 0;
    while (sent < n) {
        uint64_t now = now_ms();
        if (now >= deadline) throw NetError("tempo esgotado ao enviar");
        if (!(poll_wait(fd, POLLOUT, static_cast<int>(deadline - now)) & (POLLOUT | POLLERR | POLLHUP))) continue;
        ssize_t r = ::send(fd, data + sent, n - sent, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw NetError(std::string("send: ") + std::strerror(errno));
        }
        sent += static_cast<size_t>(r);
    }
}

void recv_exact(int fd, uint8_t* data, size_t n, int timeout_ms) {
    uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms);
    size_t got = 0;
    while (got < n) {
        uint64_t now = now_ms();
        if (now >= deadline) throw NetError("tempo esgotado ao receber");
        if (!(poll_wait(fd, POLLIN, static_cast<int>(deadline - now)) & (POLLIN | POLLERR | POLLHUP))) continue;
        ssize_t r = ::recv(fd, data + got, n - got, 0);
        if (r == 0) throw NetError("conexao encerrada pelo outro lado");
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw NetError(std::string("recv: ") + std::strerror(errno));
        }
        got += static_cast<size_t>(r);
    }
}

void shutdown_socket(int fd) { ::shutdown(fd, SHUT_RDWR); }

UdpSocket UdpSocket::open(uint16_t port) {
    UdpSocket s;
    s.fd_.reset(::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (s.fd_.valid()) {
        s.family_ = AF_INET6;
        int zero = 0;
        ::setsockopt(s.fd_.get(), IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
    } else {
        s.family_ = AF_INET;
        s.fd_.reset(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    }
    if (!s.fd_.valid()) throw NetError(std::string("socket udp: ") + std::strerror(errno));
    int buf = 4 << 20;
    ::setsockopt(s.fd_.get(), SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
    ::setsockopt(s.fd_.get(), SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
    int rc;
    if (s.family_ == AF_INET6) {
        sockaddr_in6 a;
        std::memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(port);
        rc = ::bind(s.fd_.get(), reinterpret_cast<sockaddr*>(&a), sizeof a);
    } else {
        sockaddr_in a;
        std::memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons(port);
        rc = ::bind(s.fd_.get(), reinterpret_cast<sockaddr*>(&a), sizeof a);
    }
    if (rc < 0) throw NetError("nao foi possivel abrir a porta UDP " + std::to_string(port) + ": " + std::strerror(errno));
    set_nonblocking(s.fd_.get(), true);
    sockaddr_storage ss;
    socklen_t len = sizeof ss;
    ::getsockname(s.fd_.get(), reinterpret_cast<sockaddr*>(&ss), &len);
    s.port_ = Address::from_sockaddr(reinterpret_cast<sockaddr*>(&ss), len).port();
    return s;
}

bool UdpSocket::send_to(const Address& to, const uint8_t* data, size_t n) const {
    if (family_ == AF_INET6 && to.family() == AF_INET) {
        Address m = to.mapped_v6();
        return ::sendto(fd_.get(), data, n, MSG_NOSIGNAL, m.sa(), m.len()) == static_cast<ssize_t>(n);
    }
    if (family_ == AF_INET && to.family() != AF_INET) return false;
    return ::sendto(fd_.get(), data, n, MSG_NOSIGNAL, to.sa(), to.len()) == static_cast<ssize_t>(n);
}

int UdpSocket::recv_from(uint8_t* buf, size_t cap, Address& from, int timeout_ms) const {
    if (!(poll_wait(fd_.get(), POLLIN, timeout_ms) & (POLLIN | POLLERR))) return -1;
    sockaddr_storage ss;
    socklen_t len = sizeof ss;
    ssize_t r = ::recvfrom(fd_.get(), buf, cap, MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&ss), &len);
    if (r < 0) return -1;
    from = Address::from_sockaddr(reinterpret_cast<sockaddr*>(&ss), len);
    return static_cast<int>(r);
}

}
