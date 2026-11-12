#pragma once
#include <array>
#include <cstdint>
#include <string>

#include "bytes.hpp"

namespace sp {

using Digest = std::array<uint8_t, 32>;

class Sha256 {
public:
    Sha256();
    void update(const uint8_t* data, size_t n);
    void update(const Bytes& b) { update(b.data(), b.size()); }
    Digest finish();

private:
    void block(const uint8_t* p);
    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buf_len_ = 0;
    uint64_t total_ = 0;
};

class Hmac {
public:
    explicit Hmac(const Bytes& key);
    void update(const uint8_t* data, size_t n) { inner_.update(data, n); }
    void update(const Bytes& b) { inner_.update(b); }
    Digest finish();

private:
    Sha256 inner_;
    uint8_t opad_[64];
};

Digest sha256(const uint8_t* data, size_t n);
inline Digest sha256(const Bytes& b) { return sha256(b.data(), b.size()); }
Digest hmac_sha256(const Bytes& key, const uint8_t* data, size_t n);
inline Digest hmac_sha256(const Bytes& key, const Bytes& data) { return hmac_sha256(key, data.data(), data.size()); }
std::string to_hex(const uint8_t* data, size_t n);
inline std::string to_hex(const Digest& d) { return to_hex(d.data(), d.size()); }
bool from_hex(const std::string& s, Digest& out);
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n);

}
