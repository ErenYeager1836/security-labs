#include "scanner.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>

using namespace security_labs;

void print_banner() {
    std::cout << "=========================================================\n"
              << "       security-labs // port-scanner (C++17)             \n"
              << "  Multithreaded TCP Connect Scanner & Banner Grabber     \n"
              << "=========================================================\n\n";
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  -h, --host <host>       Target IP or hostname (default: 127.0.0.1)\n"
              << "  -p, --ports <range>      Port range 'start-end' or single port (default: 1-1024)\n"
              << "  -t, --timeout <ms>       Connect timeout in milliseconds (default: 1000)\n"
              << "  -n, --threads <num>      Concurrency / thread pool size (default: 50)\n"
              << "      --no-banner          Disable service banner grabbing\n"
              << "      --help               Display this help dialog\n\n"
              << "Example:\n"
              << "  " << prog << " --host 127.0.0.1 --ports 20-100 --threads 20\n";
}

int main(int argc, char* argv[]) {
    PortScanner::initialize();

    PortScanConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            print_usage(argv[0]);
            PortScanner::cleanup();
            return 0;
        } else if ((arg == "-h" || arg == "--host") && i + 1 < argc) {
            config.host = argv[++i];
        } else if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            std::string p_str = argv[++i];
            size_t dash = p_str.find('-');
            if (dash != std::string::npos) {
                config.start_port = std::stoi(p_str.substr(0, dash));
                config.end_port = std::stoi(p_str.substr(dash + 1));
            } else {
                config.start_port = std::stoi(p_str);
                config.end_port = config.start_port;
            }
        } else if ((arg == "-t" || arg == "--timeout") && i + 1 < argc) {
            config.timeout_ms = std::stoi(argv[++i]);
        } else if ((arg == "-n" || arg == "--threads") && i + 1 < argc) {
            config.num_threads = std::stoi(argv[++i]);
        } else if (arg == "--no-banner") {
            config.grab_banner = false;
        }
    }

    print_banner();

    // Security warning on non-loopback targets
    if (!PortScanner::is_loopback(config.host)) {
        std::cout << "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                  << "[!] SECURITY NOTICE: Target host is NON-LOOPBACK (" << config.host << ")\n"
                  << "[!] Scanning external networks without prior written consent\n"
                  << "[!] is illegal under CFAA, CMA, and computer crime laws.\n"
                  << "[!] Only test systems you own or have explicit authorization for.\n"
                  << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n";
    }

    std::cout << "[*] Target Host:     " << config.host << "\n"
              << "[*] Port Range:      " << config.start_port << " -> " << config.end_port << "\n"
              << "[*] Connect Timeout: " << config.timeout_ms << " ms\n"
              << "[*] Worker Threads:  " << config.num_threads << "\n"
              << "[*] Banner Grab:     " << (config.grab_banner ? "Enabled" : "Disabled") << "\n\n";

    std::cout << "[*] Starting port scan...\n";
    auto t0 = std::chrono::steady_clock::now();

    auto progress = [](int scanned, int total) {
        int percent = static_cast<int>((scanned * 100.0) / total);
        std::cout << "\r[+] Progress: " << scanned << "/" << total 
                  << " ports (" << percent << "%) " << std::flush;
    };

    std::vector<PortResult> open_ports = PortScanner::scan_range(config, progress);
    auto t1 = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double>(t1 - t0).count();

    std::cout << "\n\n--- Scan Results ---\n";
    if (open_ports.empty()) {
        std::cout << "No open TCP ports discovered in specified range.\n";
    } else {
        std::cout << std::left << std::setw(12) << "PORT"
                  << std::setw(10) << "STATE"
                  << std::setw(22) << "SERVICE"
                  << "BANNER" << "\n";
        std::cout << std::string(65, '-') << "\n";

        for (const auto& r : open_ports) {
            std::string port_proto = std::to_string(r.port) + "/tcp";
            std::cout << std::left << std::setw(12) << port_proto
                      << std::setw(10) << "OPEN"
                      << std::setw(22) << r.service_hint
                      << (r.banner.empty() ? "-" : r.banner)
                      << "\n";
        }
    }

    std::cout << "\n[+] Finished in " << std::fixed << std::setprecision(2) << duration << "s. "
              << open_ports.size() << " open port(s) found across " 
              << (config.end_port - config.start_port + 1) << " ports scanned.\n";

    PortScanner::cleanup();
    return 0;
}
