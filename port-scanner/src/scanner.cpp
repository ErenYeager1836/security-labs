#include "scanner.hpp"

#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <unordered_map>

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
    inline int close_socket(socket_t s) { return closesocket(s); }
    inline int set_nonblocking(socket_t s, bool enable) {
        u_long mode = enable ? 1 : 0;
        return ioctlsocket(s, FIONBIO, &mode);
    }
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    using socket_t = int;
    constexpr socket_t INVALID_SOCK = -1;
    inline int close_socket(socket_t s) { return close(s); }
    inline int set_nonblocking(socket_t s, bool enable) {
        int flags = fcntl(s, F_GETFL, 0);
        if (flags < 0) return -1;
        flags = enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
        return fcntl(s, F_SETFL, flags);
    }
#endif

namespace security_labs {

static std::atomic<bool> s_initialized{false};

void PortScanner::initialize() {
    if (s_initialized.exchange(true)) return;
#ifdef _WIN32
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != 0) {
        std::cerr << "[-] WSAStartup failed: " << res << "\n";
    }
#endif
}

void PortScanner::cleanup() {
    if (!s_initialized.exchange(false)) return;
#ifdef _WIN32
    WSACleanup();
#endif
}

bool PortScanner::is_loopback(const std::string& host) {
    if (host == "localhost" || host == "127.0.0.1" || host == "::1") {
        return true;
    }
    if (host.rfind("127.", 0) == 0) {
        return true;
    }
    return false;
}

std::string PortScanner::lookup_service_name(int port) {
    static const std::unordered_map<int, std::string> s_services = {
        {21, "FTP"},
        {22, "SSH"},
        {23, "Telnet"},
        {25, "SMTP"},
        {53, "DNS"},
        {80, "HTTP"},
        {110, "POP3"},
        {143, "IMAP"},
        {443, "HTTPS"},
        {445, "Microsoft-DS (SMB)"},
        {993, "IMAPS"},
        {995, "POP3S"},
        {1433, "MS SQL Server"},
        {1521, "Oracle DB"},
        {3306, "MySQL"},
        {3389, "RDP"},
        {5432, "PostgreSQL"},
        {6379, "Redis"},
        {8000, "HTTP-Alt / Dev"},
        {8080, "HTTP-Proxy / Alt"},
        {8443, "HTTPS-Alt"},
        {9200, "Elasticsearch"},
        {27017, "MongoDB"}
    };

    auto it = s_services.find(port);
    if (it != s_services.end()) {
        return it->second;
    }
    return "Unknown";
}

PortResult PortScanner::scan_single_port(
    const std::string& host,
    int port,
    int timeout_ms,
    bool grab_banner
) {
    initialize();

    PortResult result;
    result.port = port;
    result.is_open = false;
    result.service_hint = lookup_service_name(port);

    struct addrinfo hints;
    struct addrinfo* addr_res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &addr_res) != 0 || !addr_res) {
        return result;
    }

    socket_t sock = socket(addr_res->ai_family, addr_res->ai_socktype, addr_res->ai_protocol);
    if (sock == INVALID_SOCK) {
        freeaddrinfo(addr_res);
        return result;
    }

    set_nonblocking(sock, true);

    int conn_res = connect(sock, addr_res->ai_addr, static_cast<int>(addr_res->ai_addrlen));
    freeaddrinfo(addr_res);

    bool connected = false;

    if (conn_res == 0) {
        connected = true;
    } else {
        fd_set write_set;
        fd_set err_set;
        FD_ZERO(&write_set);
        FD_ZERO(&err_set);
        FD_SET(sock, &write_set);
        FD_SET(sock, &err_set);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel_res = select(static_cast<int>(sock + 1), nullptr, &write_set, &err_set, &tv);
        if (sel_res > 0) {
            if (FD_ISSET(sock, &write_set) && !FD_ISSET(sock, &err_set)) {
                int sock_err = 0;
                socklen_t len = sizeof(sock_err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&sock_err), &len) == 0) {
                    if (sock_err == 0) {
                        connected = true;
                    }
                }
            }
        }
    }

    if (!connected) {
        close_socket(sock);
        return result;
    }

    result.is_open = true;

    // Optional Banner Grabbing
    if (grab_banner) {
        // Send a lightweight probe for web servers, or wait for server-speaks-first (SSH/FTP/SMTP)
        if (port == 80 || port == 8080 || port == 8000 || port == 8443) {
            const char* http_probe = "HEAD / HTTP/1.0\r\nUser-Agent: security-labs-scanner\r\n\r\n";
            send(sock, http_probe, static_cast<int>(std::strlen(http_probe)), 0);
        }

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);

        struct timeval banner_tv;
        banner_tv.tv_sec = 0;
        banner_tv.tv_usec = 600000; // 600ms timeout for banner response

        int sel_read = select(static_cast<int>(sock + 1), &read_set, nullptr, nullptr, &banner_tv);
        if (sel_read > 0 && FD_ISSET(sock, &read_set)) {
            char buffer[512];
            std::memset(buffer, 0, sizeof(buffer));
            int bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_read > 0) {
                std::string banner_str;
                for (int i = 0; i < bytes_read; ++i) {
                    char c = buffer[i];
                    if (c == '\r' || c == '\n') {
                        if (!banner_str.empty()) break; // Take first line
                    } else if (c >= 32 && c <= 126) {
                        banner_str += c;
                    }
                    if (banner_str.size() >= 70) break;
                }
                result.banner = banner_str;
            }
        }
    }

    close_socket(sock);
    return result;
}

std::vector<PortResult> PortScanner::scan_range(
    const PortScanConfig& config,
    std::function<void(int scanned, int total)> progress_callback
) {
    initialize();

    int start_p = std::max(1, std::min(config.start_port, config.end_port));
    int end_p = std::min(65535, std::max(config.start_port, config.end_port));
    int total_ports = (end_p - start_p) + 1;

    std::vector<PortResult> open_results;
    std::mutex results_mutex;
    std::atomic<int> current_index{0};
    std::atomic<int> completed_count{0};

    int actual_threads = std::max(1, std::min(config.num_threads, total_ports));
    std::vector<std::thread> workers;
    workers.reserve(actual_threads);

    for (int t = 0; t < actual_threads; ++t) {
        workers.emplace_back([&]() {
            while (true) {
                int offset = current_index.fetch_add(1);
                if (offset >= total_ports) break;

                int port = start_p + offset;
                PortResult r = scan_single_port(
                    config.host,
                    port,
                    config.timeout_ms,
                    config.grab_banner
                );

                if (r.is_open) {
                    std::lock_guard<std::mutex> lock(results_mutex);
                    open_results.push_back(r);
                }

                int finished = completed_count.fetch_add(1) + 1;
                if (progress_callback && (finished % 25 == 0 || finished == total_ports)) {
                    progress_callback(finished, total_ports);
                }
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) {
            w.join();
        }
    }

    // Sort results by port number ascending
    std::sort(open_results.begin(), open_results.end(), [](const PortResult& a, const PortResult& b) {
        return a.port < b.port;
    });

    return open_results;
}

static std::string escape_json(const std::string& str) {
    std::string out;
    for (char c : str) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 32) {
            // omit non-printable control bytes
        } else {
            out += c;
        }
    }
    return out;
}

std::string PortScanner::to_json(const std::string& host, const std::vector<PortResult>& results) {
    std::string json = "{\n";
    json += "  \"host\": \"" + escape_json(host) + "\",\n";
    json += "  \"open_ports_count\": " + std::to_string(results.size()) + ",\n";
    json += "  \"ports\": [\n";

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        json += "    {\n";
        json += "      \"port\": " + std::to_string(r.port) + ",\n";
        json += "      \"state\": \"" + std::string(r.is_open ? "open" : "closed") + "\",\n";
        json += "      \"service\": \"" + escape_json(r.service_hint) + "\",\n";
        json += "      \"banner\": \"" + escape_json(r.banner) + "\"\n";
        json += "    }" + std::string(i + 1 < results.size() ? "," : "") + "\n";
    }

    json += "  ]\n";
    json += "}\n";
    return json;
}

std::string PortScanner::to_csv(const std::string& host, const std::vector<PortResult>& results) {
    std::string csv = "host,port,state,service,banner\n";
    for (const auto& r : results) {
        std::string escaped_banner;
        for (char c : r.banner) {
            if (c == '"') escaped_banner += "\"\"";
            else if (c == '\r' || c == '\n') escaped_banner += ' ';
            else escaped_banner += c;
        }
        csv += host + "," + std::to_string(r.port) + "," + (r.is_open ? "open" : "closed") + "," +
               r.service_hint + ",\"" + escaped_banner + "\"\n";
    }
    return csv;
}

} // namespace security_labs
