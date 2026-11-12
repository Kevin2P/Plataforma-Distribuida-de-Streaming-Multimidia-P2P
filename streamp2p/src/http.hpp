#pragma once
#include <atomic>
#include <functional>
#include <string>
#include <thread>

#include "net.hpp"
#include "util.hpp"

namespace sp {

const char* dashboard_html();

class HttpServer {
public:
    HttpServer(uint16_t port, std::function<std::string()> status);
    ~HttpServer();
    void start();
    void stop();
    uint16_t port() const { return port_; }

private:
    void loop();
    void handle(Fd fd);
    uint16_t requested_;
    uint16_t port_ = 0;
    std::function<std::string()> status_;
    Fd listen_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    ThreadSet workers_;
};

}
