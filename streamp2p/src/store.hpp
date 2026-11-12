#pragma once
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "manifest.hpp"

namespace sp {

class ChunkStore {
public:
    explicit ChunkStore(std::string dir);
    void load();
    Manifest import_file(const std::string& path, const std::string& name, uint32_t chunk_size, uint32_t bitrate_kbps);
    bool add_manifest(const Manifest& m);
    bool manifest(const Digest& id, Manifest& out) const;
    bool put(const Digest& id, uint32_t index, const Bytes& data);
    bool get(const Digest& id, uint32_t index, Bytes& out) const;
    Bitmap bitmap(const Digest& id) const;
    std::vector<Digest> contents() const;
    bool assemble(const Digest& id, const std::string& out_path) const;

private:
    struct Entry {
        Manifest manifest;
        Bitmap have;
    };
    std::string content_dir(const Digest& id) const;
    std::string chunk_path(const Digest& id, uint32_t index) const;
    std::string dir_;
    mutable std::mutex mu_;
    std::map<std::string, Entry> entries_;
};

}
