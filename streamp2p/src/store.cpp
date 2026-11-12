#include "store.hpp"

#include <filesystem>
#include <fstream>

#include "util.hpp"

namespace fs = std::filesystem;

namespace sp {
namespace {

bool write_file(const std::string& path, const Bytes& data) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!f) return false;
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    return !ec;
}

bool read_file(const std::string& path, Bytes& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize size = f.tellg();
    if (size < 0) return false;
    out.resize(static_cast<size_t>(size));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(out.data()), size);
    return static_cast<bool>(f);
}

}

ChunkStore::ChunkStore(std::string dir) : dir_(std::move(dir)) {
    std::error_code ec;
    fs::create_directories(dir_, ec);
}

std::string ChunkStore::content_dir(const Digest& id) const { return dir_ + "/" + to_hex(id); }

std::string ChunkStore::chunk_path(const Digest& id, uint32_t index) const {
    return content_dir(id) + "/" + std::to_string(index) + ".chunk";
}

void ChunkStore::load() {
    std::error_code ec;
    for (const auto& de : fs::directory_iterator(dir_, ec)) {
        if (!de.is_directory()) continue;
        Digest id;
        if (!from_hex(de.path().filename().string(), id)) continue;
        Bytes raw;
        if (!read_file(de.path().string() + "/manifest.bin", raw)) continue;
        Manifest m;
        try {
            ByteReader r(raw);
            m = Manifest::decode(r);
            r.expect_end();
        } catch (const DecodeError&) {
            continue;
        }
        if (m.id() != id) continue;
        Bitmap have(m.chunks());
        for (size_t i = 0; i < m.chunks(); i++) {
            Bytes data;
            std::string path = chunk_path(id, static_cast<uint32_t>(i));
            if (!fs::exists(path, ec)) continue;
            if (read_file(path, data) && data.size() == m.chunk_len(i) && sha256(data) == m.hashes[i]) have.set(i);
            else fs::remove(path, ec);
        }
        std::lock_guard<std::mutex> lock(mu_);
        entries_[to_hex(id)] = Entry{m, have};
    }
}

Manifest ChunkStore::import_file(const std::string& path, const std::string& name, uint32_t chunk_size, uint32_t bitrate_kbps) {
    std::error_code ec;
    uint64_t size = fs::file_size(path, ec);
    if (ec || size == 0) throw std::runtime_error("arquivo ausente ou vazio: " + path);
    if (chunk_size < kMinChunkSize || chunk_size > kMaxChunkSize) throw std::runtime_error("tamanho de chunk invalido");
    Manifest m;
    m.name = name;
    m.size = size;
    m.chunk_size = chunk_size;
    m.bitrate_kbps = bitrate_kbps;
    if (!m.valid() && (size + chunk_size - 1) / chunk_size > kMaxChunks) throw std::runtime_error("arquivo grande demais para esse chunk");
    std::string tmp_dir = dir_ + "/.import-" + to_hex(random_bytes(6).data(), 6);
    fs::create_directories(tmp_dir, ec);
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("nao foi possivel abrir " + path);
    Bytes buf(chunk_size);
    for (uint32_t idx = 0; in; idx++) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(chunk_size));
        std::streamsize got = in.gcount();
        if (got <= 0) break;
        Bytes chunk(buf.begin(), buf.begin() + got);
        m.hashes.push_back(sha256(chunk));
        if (!write_file(tmp_dir + "/" + std::to_string(idx) + ".chunk", chunk)) throw std::runtime_error("falha ao gravar chunk");
    }
    if (!m.valid()) throw std::runtime_error("manifesto invalido (nome ou tamanho)");
    Digest id = m.id();
    if (!write_file(tmp_dir + "/manifest.bin", m.encode())) throw std::runtime_error("falha ao gravar manifesto");
    std::string final_dir = content_dir(id);
    if (fs::exists(final_dir, ec)) {
        fs::remove_all(tmp_dir, ec);
    } else {
        fs::rename(tmp_dir, final_dir, ec);
        if (ec) throw std::runtime_error("falha ao publicar o conteudo no armazenamento");
    }
    Bitmap full(m.chunks());
    for (size_t i = 0; i < m.chunks(); i++) full.set(i);
    std::lock_guard<std::mutex> lock(mu_);
    entries_[to_hex(id)] = Entry{m, full};
    return m;
}

bool ChunkStore::add_manifest(const Manifest& m) {
    if (!m.valid()) return false;
    Digest id = m.id();
    std::string key = to_hex(id);
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (entries_.count(key)) return false;
    }
    std::error_code ec;
    fs::create_directories(content_dir(id), ec);
    write_file(content_dir(id) + "/manifest.bin", m.encode());
    std::lock_guard<std::mutex> lock(mu_);
    entries_.emplace(key, Entry{m, Bitmap(m.chunks())});
    return true;
}

bool ChunkStore::manifest(const Digest& id, Manifest& out) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(to_hex(id));
    if (it == entries_.end()) return false;
    out = it->second.manifest;
    return true;
}

bool ChunkStore::put(const Digest& id, uint32_t index, const Bytes& data) {
    Manifest m;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = entries_.find(to_hex(id));
        if (it == entries_.end() || index >= it->second.manifest.chunks()) return false;
        if (it->second.have.get(index)) return true;
        m = it->second.manifest;
    }
    if (data.size() != m.chunk_len(index) || sha256(data) != m.hashes[index]) return false;
    if (!write_file(chunk_path(id, index), data)) return false;
    std::lock_guard<std::mutex> lock(mu_);
    entries_[to_hex(id)].have.set(index);
    return true;
}

bool ChunkStore::get(const Digest& id, uint32_t index, Bytes& out) const {
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = entries_.find(to_hex(id));
        if (it == entries_.end() || !it->second.have.get(index)) return false;
    }
    return read_file(chunk_path(id, index), out);
}

Bitmap ChunkStore::bitmap(const Digest& id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(to_hex(id));
    return it == entries_.end() ? Bitmap(0) : it->second.have;
}

std::vector<Digest> ChunkStore::contents() const {
    std::vector<Digest> out;
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& kv : entries_) {
        Digest d;
        if (from_hex(kv.first, d)) out.push_back(d);
    }
    return out;
}

bool ChunkStore::assemble(const Digest& id, const std::string& out_path) const {
    Manifest m;
    if (!manifest(id, m) || !bitmap(id).full()) return false;
    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    for (size_t i = 0; i < m.chunks(); i++) {
        Bytes data;
        if (!get(id, static_cast<uint32_t>(i), data)) return false;
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    return static_cast<bool>(out);
}

}
