#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "bytes.hpp"
#include "sha256.hpp"

namespace sp {

constexpr uint32_t kMinChunkSize = 1024;
constexpr uint32_t kMaxChunkSize = 1u << 20;
constexpr uint32_t kMaxChunks = 1u << 20;

class Bitmap {
public:
    explicit Bitmap(size_t n = 0) : n_(n), bits_((n + 7) / 8, 0) {}
    size_t size() const { return n_; }
    bool get(size_t i) const { return i < n_ && (bits_[i / 8] >> (i % 8) & 1); }
    void set(size_t i) {
        if (i < n_) bits_[i / 8] = static_cast<uint8_t>(bits_[i / 8] | (1u << (i % 8)));
    }
    size_t count() const {
        size_t c = 0;
        for (size_t i = 0; i < n_; i++) c += get(i) ? 1u : 0u;
        return c;
    }
    bool full() const { return count() == n_; }
    const Bytes& bytes() const { return bits_; }
    static bool from_bytes(const Bytes& raw, size_t n, Bitmap& out);

private:
    size_t n_;
    Bytes bits_;
};

struct Manifest {
    std::string name;
    uint64_t size = 0;
    uint32_t chunk_size = 0;
    uint32_t bitrate_kbps = 0;
    std::vector<Digest> hashes;

    size_t chunks() const { return hashes.size(); }
    uint32_t chunk_len(size_t idx) const;
    double chunk_duration_ms(size_t idx) const;
    Digest id() const;
    Bytes encode() const;
    static Manifest decode(ByteReader& r);
    bool valid() const;
};

}
