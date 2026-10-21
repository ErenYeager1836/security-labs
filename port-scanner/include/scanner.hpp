#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace security_labs {

struct PortScanConfig {
    std::string host = "127.0.0.1";
    int start_port = 1;
    int end_port = 1024;
    int timeout_ms = 1000;
    int num_threads = 50;
    bool grab_banner = true;
};

struct PortResult {
    int port = 0;
    bool is_open = false;
    std::string banner;
    std::string service_hint;
};

class PortScanner {
public:
    // Initializes platform socket subsystem (Winsock on Windows, no-op on POSIX)
    static void initialize();
    static void cleanup();

    // Validates whether host string resolves to a loopback address
    static bool is_loopback(const std::string& host);

    // Resolves standard well-known TCP port numbers to common protocol names
    static std::string lookup_service_name(int port);

    // Synchronously connects to a single TCP port with a non-blocking timeout
    static PortResult scan_single_port(
        const std::string& host,
        int port,
        int timeout_ms = 1000,
        bool grab_banner = true
    );

    // Scans a port range concurrently across a worker thread pool
    static std::vector<PortResult> scan_range(
        const PortScanConfig& config,
        std::function<void(int scanned, int total)> progress_callback = nullptr
    );
};

} // namespace security_labs
