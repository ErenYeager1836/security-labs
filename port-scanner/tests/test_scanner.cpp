#include "scanner.hpp"

#include <iostream>
#include <cassert>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
    #define NOMINMAX
    #endif
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    using socket_t = SOCKET;
    constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
    inline int close_sock(socket_t s) { return closesocket(s); }
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    using socket_t = int;
    constexpr socket_t INVALID_SOCK = -1;
    inline int close_sock(socket_t s) { return close(s); }
#endif

using namespace security_labs;

// Simple test TCP server that accepts connections and sends a test banner
class TestServer {
public:
    TestServer() : server_sock_(INVALID_SOCK), port_(0), running_(false) {}

    bool start() {
        PortScanner::initialize();

        server_sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_sock_ == INVALID_SOCK) return false;

        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // OS allocates free ephemeral port

        if (bind(server_sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close_sock(server_sock_);
            return false;
        }

        socklen_t addr_len = sizeof(addr);
        if (getsockname(server_sock_, reinterpret_cast<sockaddr*>(&addr), &addr_len) != 0) {
            close_sock(server_sock_);
            return false;
        }
        port_ = ntohs(addr.sin_port);

        if (listen(server_sock_, 5) != 0) {
            close_sock(server_sock_);
            return false;
        }

        running_ = true;
        server_thread_ = std::thread([this]() {
            while (running_) {
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(server_sock_, &rfds);
                timeval tv{0, 200000}; // 200ms
                int s = select(static_cast<int>(server_sock_ + 1), &rfds, nullptr, nullptr, &tv);
                if (s > 0 && FD_ISSET(server_sock_, &rfds)) {
                    sockaddr_in client_addr;
                    socklen_t clen = sizeof(client_addr);
                    socket_t client = accept(server_sock_, reinterpret_cast<sockaddr*>(&client_addr), &clen);
                    if (client != INVALID_SOCK) {
                        const char* banner = "SEC-LABS-BANNER-TEST-V1.0\r\n";
                        send(client, banner, static_cast<int>(std::strlen(banner)), 0);
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        close_sock(client);
                    }
                }
            }
        });

        return true;
    }

    void stop() {
        running_ = false;
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        if (server_sock_ != INVALID_SOCK) {
            close_sock(server_sock_);
            server_sock_ = INVALID_SOCK;
        }
    }

    ~TestServer() {
        stop();
    }

    int port() const { return port_; }

private:
    socket_t server_sock_;
    int port_;
    std::atomic<bool> running_;
    std::thread server_thread_;
};

void test_is_loopback() {
    std::cout << "[+] Running test_is_loopback...\n";
    assert(PortScanner::is_loopback("127.0.0.1"));
    assert(PortScanner::is_loopback("localhost"));
    assert(PortScanner::is_loopback("127.0.0.42"));
    assert(PortScanner::is_loopback("::1"));
    assert(!PortScanner::is_loopback("192.168.1.1"));
    assert(!PortScanner::is_loopback("8.8.8.8"));
    assert(!PortScanner::is_loopback("scanme.nmap.org"));
    std::cout << "    PASSED\n";
}

void test_lookup_service_name() {
    std::cout << "[+] Running test_lookup_service_name...\n";
    assert(PortScanner::lookup_service_name(22) == "SSH");
    assert(PortScanner::lookup_service_name(80) == "HTTP");
    assert(PortScanner::lookup_service_name(443) == "HTTPS");
    assert(PortScanner::lookup_service_name(3306) == "MySQL");
    assert(PortScanner::lookup_service_name(6379) == "Redis");
    assert(PortScanner::lookup_service_name(59999) == "Unknown");
    std::cout << "    PASSED\n";
}

void test_scan_open_port_and_banner() {
    std::cout << "[+] Running test_scan_open_port_and_banner...\n";
    TestServer server;
    assert(server.start());
    int server_port = server.port();
    assert(server_port > 0);

    PortResult res = PortScanner::scan_single_port("127.0.0.1", server_port, 1000, true);
    assert(res.is_open);
    assert(res.port == server_port);
    assert(res.banner.find("SEC-LABS-BANNER-TEST-V1.0") != std::string::npos);

    server.stop();
    std::cout << "    PASSED\n";
}

void test_scan_closed_port() {
    std::cout << "[+] Running test_scan_closed_port...\n";
    // Choose high port unlikely to be open
    int closed_port = 59876;
    PortResult res = PortScanner::scan_single_port("127.0.0.1", closed_port, 300, false);
    assert(!res.is_open);
    assert(res.port == closed_port);
    std::cout << "    PASSED\n";
}

void test_scan_range_multithreaded() {
    std::cout << "[+] Running test_scan_range_multithreaded...\n";
    TestServer server;
    assert(server.start());
    int server_port = server.port();

    PortScanConfig config;
    config.host = "127.0.0.1";
    // Scan small window surrounding our server port
    config.start_port = server_port - 2;
    config.end_port = server_port + 2;
    config.timeout_ms = 400;
    config.num_threads = 4;
    config.grab_banner = true;

    std::vector<PortResult> results = PortScanner::scan_range(config);
    bool found_server = false;
    for (const auto& r : results) {
        if (r.port == server_port && r.is_open) {
            found_server = true;
            assert(r.banner.find("SEC-LABS-BANNER") != std::string::npos);
        }
    }
    assert(found_server);

    server.stop();
    std::cout << "    PASSED\n";
}

void test_structured_export_json_and_csv() {
    std::cout << "[+] Running test_structured_export_json_and_csv...\n";
    std::vector<PortResult> sample_results = {
        {22, true, "SSH-2.0-OpenSSH_8.9", "SSH"},
        {80, true, "HTTP/1.1 200 OK", "HTTP"},
        {443, false, "", "HTTPS"}
    };

    std::string json = PortScanner::to_json("127.0.0.1", sample_results);
    assert(json.find("\"host\": \"127.0.0.1\"") != std::string::npos);
    assert(json.find("\"port\": 22") != std::string::npos);
    assert(json.find("\"service\": \"SSH\"") != std::string::npos);
    assert(json.find("\"banner\": \"SSH-2.0-OpenSSH_8.9\"") != std::string::npos);

    std::string csv = PortScanner::to_csv("127.0.0.1", sample_results);
    assert(csv.find("host,port,state,service,banner") != std::string::npos);
    assert(csv.find("127.0.0.1,22,open,SSH,\"SSH-2.0-OpenSSH_8.9\"") != std::string::npos);
    assert(csv.find("127.0.0.1,443,closed,HTTPS,\"\"") != std::string::npos);

    std::cout << "    PASSED\n";
}

int main() {
    std::cout << "=== Running port-scanner test suite ===\n";
    test_is_loopback();
    test_lookup_service_name();
    test_scan_open_port_and_banner();
    test_scan_closed_port();
    test_scan_range_multithreaded();
    test_structured_export_json_and_csv();
    std::cout << "=== All 6 port-scanner tests passed successfully! ===\n";
    return 0;
}
