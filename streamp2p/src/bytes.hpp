#pragma once
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace sp {

using Bytes = std::vector<uint8_t>;

struct DecodeError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class ByteWriter {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u16(uint16_t v) {
        u8(static_cast<uint8_t>(v >> 8));
        u8(static_cast<uint8_t>(v));
    }
    void u32(uint32_t v) {
        u16(static_cast<uint16_t>(v >> 16));
        u16(static_cast<uint16_t>(v));
    }
    void u64(uint64_t v) {
        u32(static_cast<uint32_t>(v >> 32));
        u32(static_cast<uint32_t>(v));
    }
    void raw(const uint8_t* p, size_t n) { buf_.insert(buf_.end(), p, p + n); }
    void raw(const Bytes& b) { raw(b.data(), b.size()); }
    void str(const std::string& s) {
        if (s.size() > 0xFFFF) throw DecodeError("texto longo demais");
        u16(static_cast<uint16_t>(s.size()));
        raw(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    void blob(const Bytes& b) {
        u32(static_cast<uint32_t>(b.size()));
        raw(b);
    }
    const Bytes& bytes() const { return buf_; }
    Bytes take() { return std::move(buf_); }

private:
    Bytes buf_;
};

class ByteReader {
public:
    ByteReader(const uint8_t* p, size_t n) : p_(p), n_(n) {}
    explicit ByteReader(const Bytes& b) : p_(b.data()), n_(b.size()) {}
    uint8_t u8() {
        need(1);
        return p_[pos_++];
    }
    uint16_t u16() {
        uint16_t hi = u8();
        uint16_t lo = u8();
        return static_cast<uint16_t>(hi << 8 | lo);
    }
    uint32_t u32() {
        uint32_t hi = u16();
        uint32_t lo = u16();
        return hi << 16 | lo;
    }
    uint64_t u64() {
        uint64_t hi = u32();
        uint64_t lo = u32();
        return hi << 32 | lo;
    }
    Bytes raw(size_t n) {
        need(n);
        Bytes out(p_ + pos_, p_ + pos_ + n);
        pos_ += n;
        return out;
    }
    void raw_into(uint8_t* out, size_t n) {
        need(n);
        std::memcpy(out, p_ + pos_, n);
        pos_ += n;
    }
    std::string str() {
        size_t n = u16();
        need(n);
        std::string s(reinterpret_cast<const char*>(p_ + pos_), n);
        pos_ += n;
        return s;
    }
    Bytes blob(size_t max_len) {
        size_t n = u32();
        if (n > max_len) throw DecodeError("campo maior que o limite");
        return raw(n);
    }
    size_t remaining() const { return n_ - pos_; }
    void expect_end() const {
        if (pos_ != n_) throw DecodeError("bytes sobrando no fim da mensagem");
    }

private:
    void need(size_t n) const {
        if (n > n_ - pos_) throw DecodeError("mensagem truncada");
    }
    const uint8_t* p_;
    size_t n_;
    size_t pos_ = 0;
};

}
