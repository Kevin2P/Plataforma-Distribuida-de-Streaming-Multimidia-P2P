#include "sha256.hpp"

#include <cstring>

namespace sp {
namespace {

const uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

}

Sha256::Sha256() {
    static const uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::memcpy(h_, init, sizeof h_);
}

void Sha256::block(const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = static_cast<uint32_t>(p[4 * i]) << 24 | static_cast<uint32_t>(p[4 * i + 1]) << 16 |
               static_cast<uint32_t>(p[4 * i + 2]) << 8 | static_cast<uint32_t>(p[4 * i + 3]);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + kK[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + mj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += h;
}

void Sha256::update(const uint8_t* data, size_t n) {
    if (n == 0) return;
    total_ += n;
    if (buf_len_ > 0) {
        size_t take = 64 - buf_len_ < n ? 64 - buf_len_ : n;
        std::memcpy(buf_ + buf_len_, data, take);
        buf_len_ += take;
        data += take;
        n -= take;
        if (buf_len_ == 64) {
            block(buf_);
            buf_len_ = 0;
        }
    }
    while (n >= 64) {
        block(data);
        data += 64;
        n -= 64;
    }
    if (n > 0) {
        std::memcpy(buf_, data, n);
        buf_len_ = n;
    }
}

Digest Sha256::finish() {
    uint64_t bits = total_ * 8;
    uint8_t pad[72] = {0x80};
    size_t pad_len = (buf_len_ < 56) ? 56 - buf_len_ : 120 - buf_len_;
    for (int i = 0; i < 8; i++) pad[pad_len + static_cast<size_t>(i)] = static_cast<uint8_t>(bits >> (56 - 8 * i));
    update(pad, pad_len + 8);
    Digest out;
    for (int i = 0; i < 8; i++) {
        out[static_cast<size_t>(4 * i)] = static_cast<uint8_t>(h_[i] >> 24);
        out[static_cast<size_t>(4 * i + 1)] = static_cast<uint8_t>(h_[i] >> 16);
        out[static_cast<size_t>(4 * i + 2)] = static_cast<uint8_t>(h_[i] >> 8);
        out[static_cast<size_t>(4 * i + 3)] = static_cast<uint8_t>(h_[i]);
    }
    return out;
}

Hmac::Hmac(const Bytes& key) {
    uint8_t k[64] = {0};
    if (key.size() > 64) {
        Digest d = sha256(key);
        std::memcpy(k, d.data(), d.size());
    } else if (!key.empty()) {
        std::memcpy(k, key.data(), key.size());
    }
    uint8_t ipad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad_[i] = k[i] ^ 0x5c;
    }
    inner_.update(ipad, 64);
}

Digest Hmac::finish() {
    Digest inner = inner_.finish();
    Sha256 outer;
    outer.update(opad_, 64);
    outer.update(inner.data(), inner.size());
    return outer.finish();
}

Digest sha256(const uint8_t* data, size_t n) {
    Sha256 s;
    s.update(data, n);
    return s.finish();
}

Digest hmac_sha256(const Bytes& key, const uint8_t* data, size_t n) {
    Hmac h(key);
    h.update(data, n);
    return h.finish();
}

std::string to_hex(const uint8_t* data, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (size_t i = 0; i < n; i++) {
        s.push_back(d[data[i] >> 4]);
        s.push_back(d[data[i] & 15]);
    }
    return s;
}

bool from_hex(const std::string& s, Digest& out) {
    if (s.size() != 64) return false;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < 32; i++) {
        int hi = val(s[2 * i]), lo = val(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>(hi << 4 | lo);
    }
    return true;
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

}
