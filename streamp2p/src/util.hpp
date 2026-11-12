#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "bytes.hpp"

namespace sp {

uint64_t now_ms();
uint64_t wall_ms();
Bytes random_bytes(size_t n);
bool valid_id(const std::string& s);
bool valid_name(const std::string& s);
std::string json_escape(const std::string& s);

enum class LogLevel { Quiet = 0, Info = 1, Debug = 2 };
void set_log_level(LogLevel level);
LogLevel log_level();
void logf(LogLevel level, const char* tag, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

#define LOG_INFO(tag, ...) ::sp::logf(::sp::LogLevel::Info, tag, __VA_ARGS__)
#define LOG_DEBUG(tag, ...) ::sp::logf(::sp::LogLevel::Debug, tag, __VA_ARGS__)

class ThreadSet {
public:
    ThreadSet() = default;
    ThreadSet(const ThreadSet&) = delete;
    ThreadSet& operator=(const ThreadSet&) = delete;
    ~ThreadSet() { join_all(); }
    void spawn(std::function<void()> fn);
    void join_all();
    size_t running();

private:
    struct Slot {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    void reap_locked();
    std::mutex mu_;
    std::list<Slot> slots_;
};

}
