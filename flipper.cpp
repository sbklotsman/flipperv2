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
#include <unistd.h> // Required for sysconf to get Linux page size

// ==========================================
// --- CONFIGURATION ---
// ==========================================
constexpr int POLL_INTERVAL_MS = 0; 
constexpr const char* HYPIXEL_API_URL = "https://api.hypixel.net/v2/skyblock/auctions";

struct NetMetrics {
    std::string time_sent;
    std::string time_received;
    double dns_ms;
    double tcp_ms;
    double tls_ms;
    double ttfb_ms; // For a HEAD request, TTFB is essentially the Total Time
    long code;
    std::string cache_status;
    std::string last_modified;
};

// ==========================================
// --- CALLBACKS & UTILS ---
// ==========================================
size_t HeaderCallback(char* buffer, size_t size, size_t n_items, void* userdata) {
    static_cast<std::string*>(userdata)->append(buffer, size * n_items);
    return size * n_items;
}

std::string_view getHeaderValue(std::string_view headers, std::string_view key) {
    size_t pos = headers.find(key); 
    if (pos == std::string_view::npos) {
        auto it = std::search(headers.begin(), headers.end(), key.begin(), key.end(),
            [](char c1, char c2) { return (c1 | 32) == (c2 | 32); });
        if (it != headers.end()) pos = std::distance(headers.begin(), it);
    }
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

std::string getPreciseTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string getStartupTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

double getProcessRamUsageMB() {
    std::ifstream stat_stream("/proc/self/statm", std::ios_base::in);
    if (!stat_stream.is_open()) return 0.0;
    
    long dummy, rss;
    // statm format: size resident shared text lib data dt
    stat_stream >> dummy >> rss; 
    stat_stream.close();
    
    long page_size = sysconf(_SC_PAGE_SIZE); // Dynamically grab system page size (usually 4KB)
    return (rss * page_size) / (1024.0 * 1024.0);
}

// ==========================================
// --- CORE LOGIC ---
// ==========================================
NetMetrics getHeadResponse(CURL* curl, std::string& header_bucket) {
    NetMetrics metrics = {"", "", 0, 0, 0, 0, 0, "", ""};
    
    if(curl) {                
        header_bucket.clear();
        
        curl_easy_setopt(curl, CURLOPT_URL, HYPIXEL_API_URL);            
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);  
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1); 
        
        // THIS IS THE MAGIC SWITCH FOR A 'HEAD' REQUEST
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_bucket);

        metrics.time_sent = getPreciseTimestamp();
        curl_easy_perform(curl); 
        metrics.time_received = getPreciseTimestamp();

        double dns = 0, conn = 0, tls = 0, pre = 0, start = 0;
        curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &dns);
        curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &conn);
        curl_easy_getinfo(curl, CURLINFO_APPCONNECT_TIME, &tls);
        curl_easy_getinfo(curl, CURLINFO_PRETRANSFER_TIME, &pre);
        curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &start);

        // --- BUG FIX: Clamp any negative telemetry values to zero ---
        metrics.dns_ms = std::max(0.0, dns * 1000.0);
        metrics.tcp_ms = std::max(0.0, (conn - dns) * 1000.0);
        metrics.tls_ms = std::max(0.0, (tls - conn) * 1000.0);
        metrics.ttfb_ms = std::max(0.0, (start - pre) * 1000.0);
        
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &metrics.code);
        metrics.cache_status = std::string(getHeaderValue(header_bucket, "CF-Cache-Status:"));
        metrics.last_modified = std::string(getHeaderValue(header_bucket, "Last-Modified:"));
    }
    return metrics;
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT); 
    CURL* shared_curl_handle = curl_easy_init(); 
    
    std::string header_buffer;
    header_buffer.reserve(4096);

    std::string previous_last_modified = "";

    // --- SETUP DESCRIPTIVE CSV LOGGING ---
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

        double current_ram_mb = 0.0; // Cache RAM so we don't query the OS every millisecond

        while (true) {
            auto total_iter_start = std::chrono::high_resolution_clock::now();
            
            NetMetrics net = getHeadResponse(shared_curl_handle, header_buffer);
            bool is_new_data = false;
            bool trigger_hibernation = false; 

            // Check if the Last-Modified header changed
            if (!net.last_modified.empty() && net.last_modified != "UNKNOWN" && net.last_modified != previous_last_modified) {
                if (!previous_last_modified.empty()) { 
                    is_new_data = true;
                    trigger_hibernation = true;
                    
                    // Update RAM only when we secure data
                    current_ram_mb = getProcessRamUsageMB(); 
                    
                    std::cout << "\n==================================================\n";
                    std::cout << "[!] NEW HEADERS DETECTED!\n";
                    std::cout << "[!] SECURED AT: " << getPreciseTimestamp() << "\n";
                    std::cout << "==================================================\n";
                    
                    // ---> THIS IS WHERE YOUR 'GET' TRIPWIRE WILL GO <---
                }
                previous_last_modified = net.last_modified;
            }

            auto total_iter_end = std::chrono::high_resolution_clock::now();
            int64_t total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_iter_end - total_iter_start).count();

            // Console Output (Only print full stats if we found new data to keep terminal clean)
            if (is_new_data) {
                std::cout << "[NET] TTFB: " << (int)net.ttfb_ms << "ms | Code: " << net.code << " | CF: " << net.cache_status << "\n";
                std::cout << "[SYS] RAM: " << std::fixed << std::setprecision(1) << current_ram_mb << " MB | **TOTAL**: " << total_ms << "ms\n";
            }

            // CSV Output (STILL 100% ACTIVE AND UNCHANGED)
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

            // THE CONTROLLED SEVER
            if (trigger_hibernation) {
                std::cout << "[SYS] Data secured. Destroying connection pool and entering 50s hibernation...\n\n";
                
                curl_easy_cleanup(shared_curl_handle); 
                std::this_thread::sleep_for(std::chrono::seconds(50));
                shared_curl_handle = curl_easy_init(); 

                std::cout << "[SYS] Waking up at " << getPreciseTimestamp() << "! Fresh connection pool ready. Engaging hyper-polling...\n";
                continue; 
            }

            // Calculate Sleep
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