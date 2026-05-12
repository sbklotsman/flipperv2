#include <iostream>
#include <string>
#include <string_view>
#include <fstream>
#include <chrono>     
#include <curl/curl.h>
#include <thread>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <unistd.h> 

// Global execution settings. POLL_INTERVAL_MS is set to 0 for maximum unthrottled hyper-polling.
constexpr int POLL_INTERVAL_MS = 0; 
constexpr const char* HYPIXEL_API_URL = "https://api.hypixel.net/v2/skyblock/auctions";

// Data container for a single network request's telemetry.
struct NetMetrics {
    std::string time_sent;
    std::string time_received;
    double dns_ms;
    double tcp_ms;
    double tls_ms;
    double ttfb_ms; 
    long code;
    std::string cache_status;
    std::string last_modified;
};

// libcurl callback function. Whenever libcurl receives data from the network, it passes it here.
// We append the raw byte stream directly into our pre-allocated C++ string buffer.
size_t HeaderCallback(char* buffer, size_t size, size_t n_items, void* userdata) {
    static_cast<std::string*>(userdata)->append(buffer, size * n_items);
    return size * n_items;
}

// High-performance header extraction. 
// Uses std::string_view to scan the header text without copying any memory (zero-copy).
// Employs a bitwise OR operation (c | 32) for ultra-fast, case-insensitive character matching.
std::string_view getHeaderValue(std::string_view headers, std::string_view key) {
    size_t pos = headers.find(key); 
    if (pos == std::string_view::npos) {
        auto it = std::search(headers.begin(), headers.end(), key.begin(), key.end(),
            [](char c1, char c2) { return (c1 | 32) == (c2 | 32); });
        if (it != headers.end()) pos = std::distance(headers.begin(), it);
    }
    
    // If the key is found, it isolates the value by trimming leading whitespace and stopping at the carriage return (\r\n).
    if (pos != std::string_view::npos) {
        pos += key.length();
        size_t value_end = headers.find("\r\n", pos);
        if (value_end != std::string_view::npos) {
            size_t actual_start = headers.find_first_not_of(" \t", pos);
            if (actual_start != std::string_view::npos && actual_start < value_end) {
                return headers.substr(actual_start, value_end - actual_start);
            }
        }
    }
    return "UNKNOWN";
}

// Generates a millisecond-precise HH:MM:SS.ms timestamp for network tracking.
std::string getPreciseTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

// Generates a standard YYYY-MM-DD HH:MM:SS timestamp for CSV session initialization.
std::string getStartupTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Tracks process memory footprint with zero overhead.
// this reads the Linux kernel's virtual memory map directly.
double getProcessRamUsageMB() {
    std::ifstream stat_stream("/proc/self/statm", std::ios_base::in);
    if (!stat_stream.is_open()) return 0.0;
    
    long dummy, rss;
    stat_stream >> dummy >> rss; 
    stat_stream.close();
    
    // Converts the raw memory pages into Megabytes based on the system's hardware page size
    long page_size = sysconf(_SC_PAGE_SIZE); 
    return (rss * page_size) / (1024.0 * 1024.0);
}

// Executes a single HTTP HEAD request to Cloudflare.
NetMetrics getHeadResponse(CURL* curl, std::string& header_bucket) {
    NetMetrics metrics = {"", "", 0, 0, 0, 0, 0, "", ""};
    
    if(curl) {                
        header_bucket.clear();
        
        curl_easy_setopt(curl, CURLOPT_URL, HYPIXEL_API_URL);            
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);  
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1); 
        
        // Setts CURLOPT_NOBODY to 1L to force a HEAD request
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_bucket);

        metrics.time_sent = getPreciseTimestamp();
        curl_easy_perform(curl); 
        metrics.time_received = getPreciseTimestamp();

        // Retrieve raw network timings directly from libcurl.
        double dns = 0, conn = 0, tls = 0, pre = 0, start = 0;
        curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &dns);
        curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &conn);
        curl_easy_getinfo(curl, CURLINFO_APPCONNECT_TIME, &tls);
        curl_easy_getinfo(curl, CURLINFO_PRETRANSFER_TIME, &pre);
        curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &start);

        // Calculate exact phase durations. max(0.0) to prevent linux from returning negative time
        metrics.dns_ms = std::max(0.0, dns * 1000.0);
        metrics.tcp_ms = std::max(0.0, (conn - dns) * 1000.0);
        metrics.tls_ms = std::max(0.0, (tls - conn) * 1000.0);
        metrics.ttfb_ms = std::max(0.0, (start - pre) * 1000.0);
        
        // Extract the metadata needed to determine if the payload is fresh.
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &metrics.code);
        metrics.cache_status = std::string(getHeaderValue(header_bucket, "CF-Cache-Status:"));
        metrics.last_modified = std::string(getHeaderValue(header_bucket, "Last-Modified:"));
    }
    return metrics;
}

int main() {
    // Initialize libcurl state and connection pool.
    curl_global_init(CURL_GLOBAL_DEFAULT); 
    CURL* shared_curl_handle = curl_easy_init(); 
    
    // Pre-allocate the header buffer string to 4KB to prevent dynamic resizing by Linux
    std::string header_buffer;
    header_buffer.reserve(4096);

    std::string previous_last_modified = "";

    // Open telemetry CSV in append mode and write the column headers.
    std::ofstream csvFile("head_metrics.csv", std::ios_base::app);
    csvFile << "\n--- HEAD REQUEST BASELINE @ " << getStartupTimestamp() << " ---\n";
    csvFile << "Time Request Sent,"
            << "Time Headers Received,"
            << "Is New Data Detected,"
            << "Target Polling Interval (ms),"
            << "DNS Lookup Time (ms),"
            << "TCP Handshake Time (ms),"
            << "TLS Handshake Time (ms),"
            << "Time to First Byte (ms),"
            << "Total Iteration Lifecycle (ms),"
            << "Process RAM Usage (MB),"
            << "HTTP Response Code,"
            << "Cloudflare Cache Status\n";

    if(shared_curl_handle) { 
        std::cout << "Starting HEAD-Only Ghost Poller...\n\n";

        double current_ram_mb = 0.0; 

        // Beginning of Loop. Runs indefinitely, executing the HEAD requests and managing API synchronization.
        while (true) {
            auto total_iter_start = std::chrono::high_resolution_clock::now();
            
            NetMetrics net = getHeadResponse(shared_curl_handle, header_buffer);
            bool is_new_data = false;
            bool trigger_hibernation = false; 

            // Checks if the 'Last-Modified' header has changed since the last poll.
            // If it has changed, we have found an approximation of when the API updated.
            if (!net.last_modified.empty() && net.last_modified != "UNKNOWN" && net.last_modified != previous_last_modified) {
                if (!previous_last_modified.empty()) { 
                    is_new_data = true;
                    trigger_hibernation = true;
                    
                    // Update RAM only upon securing data to not add extra latency during active polling.
                    current_ram_mb = getProcessRamUsageMB(); 
                    
                    std::cout << "\n==================================================\n";
                    std::cout << "[!] NEW HEADERS DETECTED!\n";
                    std::cout << "[!] SECURED AT: " << getPreciseTimestamp() << "\n";
                    std::cout << "==================================================\n";
                    
                } else {
                    // Code for first run of flipper to establish baseline
                    std::cout << "[SYS] Initial connection established. Baseline locked to: " << net.last_modified << "\n";
                    std::cout << "[SYS] Hyper-polling silently until the first data drop...\n";
                }
                previous_last_modified = net.last_modified;
            }

            auto total_iter_end = std::chrono::high_resolution_clock::now();
            int64_t total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_iter_end - total_iter_start).count();

            // Terminal output is restricted to only print when new data is found to prevent std::cout latency
            if (is_new_data) {
                std::cout << "[NET] TTFB: " << (int)net.ttfb_ms << "ms | Code: " << net.code << " | CF: " << net.cache_status << "\n";
                std::cout << "[SYS] RAM: " << std::fixed << std::setprecision(1) << current_ram_mb << " MB | **TOTAL**: " << total_ms << "ms\n";
            }

            // Flush metrics to csv
            csvFile << net.time_sent << ","
                    << net.time_received << ","
                    << (is_new_data ? "YES" : "NO") << "," 
                    << POLL_INTERVAL_MS << ","
                    << net.dns_ms << "," 
                    << net.tcp_ms << "," 
                    << net.tls_ms << "," 
                    << net.ttfb_ms << "," 
                    << total_ms << "," 
                    << current_ram_mb << ","
                    << net.code << "," 
                    << net.cache_status << "\n";
            csvFile.flush(); 

            // Destroys the connection pool and sleeps for 50s to forces a fresh TCP/TLS handshake 
            // upon waking, guaranteeing Cloudflare will not drop the connection right before the next drop.
            if (trigger_hibernation) {
                std::cout << "[SYS] Data secured. Destroying connection pool and entering 50s hibernation...\n\n";
                
                curl_easy_cleanup(shared_curl_handle); 
                std::this_thread::sleep_for(std::chrono::seconds(50));
                shared_curl_handle = curl_easy_init(); 

                std::cout << "[SYS] Waking up at " << getPreciseTimestamp() << "! Fresh connection pool ready. Engaging hyper-polling...\n";
                continue; 
            }

            // Normal sleep calculation for standard polling intervals.
            auto sleep_calc_end = std::chrono::high_resolution_clock::now();
            int64_t elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(sleep_calc_end - total_iter_start).count();
            
            int64_t sleep_time = POLL_INTERVAL_MS - elapsed_ms;
            if (sleep_time > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));
            }
        }
        curl_easy_cleanup(shared_curl_handle); 
    }

    csvFile.close();
    curl_global_cleanup(); 
    return 0;              
}