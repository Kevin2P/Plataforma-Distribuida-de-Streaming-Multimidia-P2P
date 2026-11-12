#pragma once
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace sp {

struct LinkProfile {
    double loss = 0.0;
    uint32_t delay_ms = 0;
    uint32_t jitter_ms = 0;
    uint64_t rate_bps = 0;
    double corrupt = 0.0;
    uint64_t seed = 1;
    bool shapes() const { return delay_ms > 0 || jitter_ms > 0 || rate_bps > 0; }
};

class Rng {
public:
    explicit Rng(uint64_t seed) : s_(seed ? seed : 1) {}
    uint64_t next() {
        uint64_t z = (s_ += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    double unit() { return static_cast<double>(next() >> 11) * (1.0 / 9007199254740992.0); }
    uint32_t below(uint32_t n) { return n == 0 ? 0 : static_cast<uint32_t>(next() % n); }

private:
    uint64_t s_;
};

class SharedRng {
public:
    explicit SharedRng(uint64_t seed) : rng_(seed) {}
    double unit() {
        std::lock_guard<std::mutex> lock(mu_);
        return rng_.unit();
    }
    uint32_t below(uint32_t n) {
        std::lock_guard<std::mutex> lock(mu_);
        return rng_.below(n);
    }

private:
    std::mutex mu_;
    Rng rng_;
};

class Pacer {
public:
    explicit Pacer(uint64_t rate_bps) : rate_(rate_bps) {}
    uint64_t reserve(size_t bytes, uint64_t now_ms);

private:
    std::mutex mu_;
    uint64_t rate_;
    double next_free_ = 0.0;
};

class DelayLine {
public:
    DelayLine();
    ~DelayLine();
    DelayLine(const DelayLine&) = delete;
    DelayLine& operator=(const DelayLine&) = delete;
    void schedule(uint64_t due_ms, std::function<void()> fn);
    size_t pending();

private:
    struct Item {
        uint64_t due;
        uint64_t seq;
        std::function<void()> fn;
    };
    struct Later {
        bool operator()(const Item& a, const Item& b) const { return a.due != b.due ? a.due > b.due : a.seq > b.seq; }
    };
    void run();
    std::mutex mu_;
    std::condition_variable cv_;
    std::priority_queue<Item, std::vector<Item>, Later> queue_;
    uint64_t seq_ = 0;
    bool stop_ = false;
    std::thread thread_;
};

}
