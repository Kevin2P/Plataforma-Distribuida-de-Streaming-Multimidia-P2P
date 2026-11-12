#include "emulation.hpp"

#include <algorithm>
#include <chrono>

#include "util.hpp"

namespace sp {

uint64_t Pacer::reserve(size_t bytes, uint64_t now_ms) {
    if (rate_ == 0) return now_ms;
    std::lock_guard<std::mutex> lock(mu_);
    double start = std::max(static_cast<double>(now_ms), next_free_);
    double duration = static_cast<double>(bytes) * 8000.0 / static_cast<double>(rate_);
    next_free_ = start + duration;
    return static_cast<uint64_t>(next_free_);
}

DelayLine::DelayLine() : thread_([this] { run(); }) {}

DelayLine::~DelayLine() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void DelayLine::schedule(uint64_t due_ms, std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        queue_.push(Item{due_ms, seq_++, std::move(fn)});
    }
    cv_.notify_all();
}

size_t DelayLine::pending() {
    std::lock_guard<std::mutex> lock(mu_);
    return queue_.size();
}

void DelayLine::run() {
    std::unique_lock<std::mutex> lock(mu_);
    while (!stop_) {
        if (queue_.empty()) {
            cv_.wait(lock);
            continue;
        }
        uint64_t now = now_ms();
        uint64_t due = queue_.top().due;
        if (due > now) {
            cv_.wait_for(lock, std::chrono::milliseconds(due - now));
            continue;
        }
        Item item = queue_.top();
        queue_.pop();
        lock.unlock();
        item.fn();
        lock.lock();
    }
}

}
