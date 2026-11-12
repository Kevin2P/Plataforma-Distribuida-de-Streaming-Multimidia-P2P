#include "manifest.hpp"

#include "util.hpp"

namespace sp {

bool Bitmap::from_bytes(const Bytes& raw, size_t n, Bitmap& out) {
    if (raw.size() != (n + 7) / 8) return false;
    Bitmap b(n);
    b.bits_ = raw;
    if (n % 8 != 0 && !b.bits_.empty()) b.bits_.back() = static_cast<uint8_t>(b.bits_.back() & ((1u << (n % 8)) - 1));
    out = std::move(b);
    return true;
}

uint32_t Manifest::chunk_len(size_t idx) const {
    if (idx >= hashes.size()) return 0;
    if (idx + 1 < hashes.size()) return chunk_size;
    return static_cast<uint32_t>(size - static_cast<uint64_t>(chunk_size) * (hashes.size() - 1));
}

double Manifest::chunk_duration_ms(size_t idx) const {
    if (bitrate_kbps == 0) return 0.0;
    return static_cast<double>(chunk_len(idx)) * 8.0 / static_cast<double>(bitrate_kbps);
}

bool Manifest::valid() const {
    if (!valid_name(name)) return false;
    if (chunk_size < kMinChunkSize || chunk_size > kMaxChunkSize) return false;
    if (size == 0 || size > static_cast<uint64_t>(chunk_size) * kMaxChunks || bitrate_kbps > 1000000) return false;
    uint64_t n = (size + chunk_size - 1) / chunk_size;
    return n >= 1 && n == hashes.size();
}

Bytes Manifest::encode() const {
    ByteWriter w;
    w.str(name);
    w.u64(size);
    w.u32(chunk_size);
    w.u32(bitrate_kbps);
    w.u32(static_cast<uint32_t>(hashes.size()));
    for (const Digest& d : hashes) w.raw(d.data(), d.size());
    return w.take();
}

Manifest Manifest::decode(ByteReader& r) {
    Manifest m;
    m.name = r.str();
    m.size = r.u64();
    m.chunk_size = r.u32();
    m.bitrate_kbps = r.u32();
    uint32_t n = r.u32();
    if (n > kMaxChunks || static_cast<uint64_t>(n) * 32 > r.remaining()) throw DecodeError("manifesto invalido");
    m.hashes.resize(n);
    for (uint32_t i = 0; i < n; i++) r.raw_into(m.hashes[i].data(), 32);
    if (!m.valid()) throw DecodeError("manifesto invalido");
    return m;
}

Digest Manifest::id() const {
    ByteWriter w;
    const char tag[4] = {'S', 'P', 'M', '1'};
    w.raw(reinterpret_cast<const uint8_t*>(tag), 4);
    w.raw(encode());
    return sha256(w.bytes());
}

}
