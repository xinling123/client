#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <queue>
#include <atomic>
#include <fstream>
#include <sstream>
#include <regex>
#include <future>
#include <memory>
#include <algorithm>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <csignal>
#include <cctype>
#include <cmath>

#ifdef _WIN32
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <pdh.h>
    #include <psapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "pdh.lib")
    #pragma comment(lib, "psapi.lib")
#else
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/statvfs.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/sysinfo.h>
    #include <dirent.h>
    #include <sys/select.h>
#endif

#include <curl/curl.h>
// 尝试使用系统安装的nlohmann/json，如果没有则使用简化版本
#ifdef __has_include
    #if __has_include(<nlohmann/json.hpp>)
        #include <nlohmann/json.hpp>
    #else
        #include "json_simple.hpp"
    #endif
#else
    // 对于不支持__has_include的编译器，默认尝试系统库
    #include <nlohmann/json.hpp>
#endif

using json = nlohmann::json;
using namespace std;

class ServerMonitor {
private:
    string uuid, client_id, url;
    string server_ip;
    int server_port;
    string last_successful_server_ip;  // 保存上次成功的服务器IP
    int last_successful_server_port;   // 保存上次成功的服务器端口
    string ipv4, ipv6, priority, country_code, emoji;
    
    struct PingConfig {
        string host;
        int port;
        string name;
    };
    
    struct DockerContainer {
        string id;
        string name;
        string status;
        string cpu_usage = "null";
        string memory_usage = "null";
        string rx_speed = "null";
        string tx_speed = "null";
        uint64_t prev_rx_bytes = 0;
        uint64_t prev_tx_bytes = 0;
        chrono::steady_clock::time_point prev_time;
    };
    
    map<string, PingConfig> ping_configs;
    map<string, double> lost_rates;
    map<string, int> ping_times;
    map<string, double> net_speed;
    map<string, uint64_t> disk_io;
    map<string, json> docker_dict;
    
    atomic<bool> running{true};
    atomic<bool> threading_start{false};
    mutex ping_config_lock;
    mutex docker_lock;
    
    ofstream log_file;
    
public:
    ServerMonitor(const string& uuid, const string& client_id, const string& url)
        : uuid(uuid), client_id(client_id), url(url), server_port(0), 
          last_successful_server_port(0) {
        
        ping_configs["10010"] = {"cu.tz.cloudcpp.com", 80, ""};
        ping_configs["189"] = {"ct.tz.cloudcpp.com", 80, ""};
        ping_configs["10086"] = {"cm.tz.cloudcpp.com", 80, ""};
        
        lost_rates["10010"] = 0.0;
        lost_rates["189"] = 0.0;
        lost_rates["10086"] = 0.0;
        
        ping_times["10010"] = 0;
        ping_times["189"] = 0;
        ping_times["10086"] = 0;
        
        net_speed["netrx"] = 0.0;
        net_speed["nettx"] = 0.0;
        disk_io["read"] = 0;
        disk_io["write"] = 0;
        
        log_file.open("/root/server_watch.log", ios::app);
        
        #ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        #endif
        
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    ~ServerMonitor() {
        running = false;
        if (log_file.is_open()) {
            log_file.close();
        }
        #ifdef _WIN32
        WSACleanup();
        #endif
        curl_global_cleanup();
    }
    
    void log_info(const string& message) {
        auto now = chrono::system_clock::now();
        auto time_t = chrono::system_clock::to_time_t(now);
        auto tm = *localtime(&time_t);
        
        stringstream ss;
        ss << put_time(&tm, "%Y-%m-%d %H:%M:%S") << " - INFO - " << message << endl;
        
        cout << ss.str();
        if (log_file.is_open()) {
            log_file << ss.str();
            log_file.flush();
        }
    }
    
    // 从JSON字符串中解析指定字段的值
    string parse_json_field(const string& json_str, const string& field_name) {
        string search_pattern = "\"" + field_name + "\":";
        size_t pos = json_str.find(search_pattern);
        if (pos != string::npos) {
            pos = json_str.find("\"", pos + search_pattern.length());
            if (pos != string::npos) {
                pos++;
                size_t end_pos = json_str.find("\"", pos);
                if (end_pos != string::npos) {
                    return json_str.substr(pos, end_pos - pos);
                }
            }
        }
        return "";
    }

    // Unicode转义序列解码函数
    string decode_unicode_escapes(const string& str) {
        string result;
        for (size_t i = 0; i < str.length(); ++i) {
            if (str[i] == '\\' && i + 5 < str.length() && str[i + 1] == 'u') {
                // 解析 \uXXXX 格式的Unicode转义
                string hex_str = str.substr(i + 2, 4);
                try {
                    unsigned int code_point = stoul(hex_str, nullptr, 16);
                    
                    // 简化的UTF-8编码（仅处理基本多文种平面）
                    if (code_point <= 0x7F) {
                        result += static_cast<char>(code_point);
                    } else if (code_point <= 0x7FF) {
                        result += static_cast<char>(0xC0 | (code_point >> 6));
                        result += static_cast<char>(0x80 | (code_point & 0x3F));
                    } else if (code_point <= 0xFFFF) {
                        result += static_cast<char>(0xE0 | (code_point >> 12));
                        result += static_cast<char>(0x80 | ((code_point >> 6) & 0x3F));
                        result += static_cast<char>(0x80 | (code_point & 0x3F));
                    }
                    
                    i += 5; // 跳过整个\uXXXX序列
                } catch (...) {
                    // 如果解析失败，保持原样
                    result += str[i];
                }
            } else {
                result += str[i];
            }
        }
        return result;
    }
    
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, string* s) {
        size_t newLength = size * nmemb;
        s->append((char*)contents, newLength);
        return newLength;
    }
    
    string http_get(const string& url) {
        CURL* curl;
        string response;
        
        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
        
        return response;
    }
    
    string http_post(const string& url, const string& data = "") {
        CURL* curl;
        string response;
        
        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
        
        return response;
    }
    
    void get_client_ip() {
        try {
            priority = http_post("https://test.ipw.cn");
            if (!priority.empty()) {
                string ip_info_url = "http://ipwho.is/" + priority;
                string ip_info = http_get(ip_info_url);
                if (!ip_info.empty()) {
                    json js = json::parse(ip_info);

                    log_info("IP info: " + ip_info);
                    country_code = js.value("country_code", "");
                    log_info("Country code: " + country_code);
                    
                    // 直接从解析后的JSON对象中提取flag字段，与Python版本保持一致
                    try {
                        if (js.find("flag") != js.end() && !js["flag"].is_null()) {
                            emoji = js["flag"].dump(); // 将flag对象转换为JSON字符串
                            log_info("Flag JSON: " + emoji);
                        } else {
                            emoji = "{}";
                            log_info("No flag field found, using empty object");
                        }
                    } catch (const exception& e) {
                        emoji = "{}";
                        log_info("Failed to extract flag JSON: " + string(e.what()));
                    }
                }
            }
        } catch (...) {
            priority = "";
            country_code = "";
            emoji = "";
        }
        
        try {
            ipv4 = http_get("https://4.ipw.cn/");
        } catch (...) {
            ipv4 = "";
        }
        
        try {
            ipv6 = http_get("https://6.ipw.cn/");
        } catch (...) {
            ipv6 = "";
        }
        
        log_info("Client IP info: " + priority + ", " + country_code + ", " + emoji + ", " + ipv4 + ", " + ipv6);
    }
    
    pair<string, int> get_server_ip_with_retry(int max_retries = 5, int delay_seconds = 10) {
        for (int attempt = 1; attempt <= max_retries; attempt++) {
            try {
                log_info("Attempting to get server IP (attempt " + to_string(attempt) + "/" + to_string(max_retries) + ")");
                string response = http_get(url);
                
                if (response.empty()) {
                    log_info("Empty response from server, attempt " + to_string(attempt) + " failed");
                    if (attempt < max_retries) {
                        log_info("Waiting " + to_string(delay_seconds) + " seconds before retry...");
                        this_thread::sleep_for(chrono::seconds(delay_seconds));
                        continue;
                    }
                } else {
                    json js = json::parse(response);
                    
                    string server_ipv4 = js[0];
                    int port = js[2];
                    
                    // 保存成功获取的IP和端口
                    last_successful_server_ip = server_ipv4;
                    last_successful_server_port = port;
                    
                    log_info("Successfully got server IP: " + server_ipv4 + ":" + to_string(port));
                    return {server_ipv4, port};
                }
            } catch (const exception& e) {
                log_info("Failed to get server IP (attempt " + to_string(attempt) + "): " + string(e.what()));
                if (attempt < max_retries) {
                    log_info("Waiting " + to_string(delay_seconds) + " seconds before retry...");
                    this_thread::sleep_for(chrono::seconds(delay_seconds));
                }
            }
        }
        
        // 如果所有重试都失败，尝试使用上次成功的IP和端口
        if (!last_successful_server_ip.empty() && last_successful_server_port > 0) {
            log_info("All retries failed, using last successful server IP: " + 
                    last_successful_server_ip + ":" + to_string(last_successful_server_port));
            return {last_successful_server_ip, last_successful_server_port};
        }
        
        log_info("Failed to get server IP after " + to_string(max_retries) + " attempts and no previous successful connection");
        return {"", 0};
    }
    
    pair<string, int> get_server_ip() {
        return get_server_ip_with_retry();
    }
    
    vector<int> get_cpu_usage() {
        vector<int> cpu_percentages;
        
        #ifdef _WIN32
        // Windows实现 - 简化版本
        cpu_percentages.push_back(0);
        return cpu_percentages;
        #else
        // Linux实现 - 读取/proc/stat来计算真实CPU使用率
        static vector<vector<uint64_t>> prev_cpu_times;
        vector<vector<uint64_t>> curr_cpu_times;
        
        ifstream stat_file("/proc/stat");
        if (!stat_file.is_open()) {
            cpu_percentages.push_back(0);
            return cpu_percentages;
        }
        
        string line;
        int cpu_index = -1;
        
        while (getline(stat_file, line)) {
            if (line.substr(0, 3) == "cpu") {
                if (line.length() > 4 && isdigit(line[3])) {
                    // 单个CPU核心 (cpu0, cpu1, ...)
                    cpu_index++;
                } else if (line.substr(0, 4) == "cpu ") {
                    // 总CPU (cpu )
                    continue; // 跳过总CPU，我们计算各个核心的
                } else {
                    continue;
                }
                
                // 解析CPU时间
                stringstream ss(line);
                string cpu_name;
                uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
                
                ss >> cpu_name >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
                
                vector<uint64_t> times = {user, nice, system, idle, iowait, irq, softirq, steal};
                curr_cpu_times.push_back(times);
            }
        }
        stat_file.close();
        
        // 如果是第一次调用，初始化prev_cpu_times
        if (prev_cpu_times.empty()) {
            prev_cpu_times = curr_cpu_times;
            // 第一次调用返回0
            for (size_t i = 0; i < curr_cpu_times.size(); i++) {
                cpu_percentages.push_back(0);
            }
            return cpu_percentages;
        }
        
        // 计算每个CPU核心的使用率
        for (size_t i = 0; i < curr_cpu_times.size() && i < prev_cpu_times.size(); i++) {
            // 计算总时间差
            uint64_t prev_idle = prev_cpu_times[i][3] + prev_cpu_times[i][4]; // idle + iowait
            uint64_t curr_idle = curr_cpu_times[i][3] + curr_cpu_times[i][4];
            
            uint64_t prev_total = 0, curr_total = 0;
            for (int j = 0; j < 8; j++) {
                prev_total += prev_cpu_times[i][j];
                curr_total += curr_cpu_times[i][j];
            }
            
            uint64_t total_diff = curr_total - prev_total;
            uint64_t idle_diff = curr_idle - prev_idle;
            
            // 计算使用率并转换为整数
            int usage = 0;
            if (total_diff > 0) {
                double usage_double = (double)(total_diff - idle_diff) / total_diff * 100.0;
                if (usage_double < 0) usage_double = 0.0;
                if (usage_double > 100.0) usage_double = 100.0;
                usage = static_cast<int>(round(usage_double)); // 四舍五入转换为整数
            }
            
            cpu_percentages.push_back(usage);
        }
        
        // 更新prev_cpu_times
        prev_cpu_times = curr_cpu_times;
        
        return cpu_percentages;
        #endif
    }
    
    vector<double> get_load_average() {
        vector<double> load_avg(3, 0.0);
        
        #ifndef _WIN32
        ifstream loadavg_file("/proc/loadavg");
        if (loadavg_file.is_open()) {
            loadavg_file >> load_avg[0] >> load_avg[1] >> load_avg[2];
        }
        #endif
        
        return load_avg;
    }
    
    string get_cpu_model() {
        #ifdef _WIN32
        return "Windows CPU";
        #else
        ifstream cpuinfo("/proc/cpuinfo");
        string line;
        while (getline(cpuinfo, line)) {
            if (line.find("model name") != string::npos) {
                size_t pos = line.find(":");
                if (pos != string::npos) {
                    return line.substr(pos + 2);
                }
            }
        }
        return "Unknown CPU";
        #endif
    }
    
    string get_system_version() {
        #ifdef _WIN32
        return "Windows";
        #else
        struct utsname buffer;
        if (uname(&buffer) == 0) {
            return string(buffer.sysname) + " " + string(buffer.release);
        }
        return "Unknown";
        #endif
    }
    
    string get_uptime() {
        #ifdef _WIN32
        // Windows: 获取系统运行时间（毫秒）
        ULONGLONG uptime_ms = GetTickCount64();
        uint64_t uptime_seconds = uptime_ms / 1000;
        #else
        // Linux: 从/proc/uptime读取系统运行时间
        ifstream uptime_file("/proc/uptime");
        double uptime_seconds_double = 0.0;
        if (uptime_file.is_open()) {
            uptime_file >> uptime_seconds_double;
            uptime_file.close();
        }
        uint64_t uptime_seconds = static_cast<uint64_t>(uptime_seconds_double);
        #endif
        
        // 计算系统启动时间 = 当前时间 - 运行时间
        auto now = chrono::system_clock::now();
        auto boot_time = now - chrono::seconds(uptime_seconds);
        auto boot_time_t = chrono::system_clock::to_time_t(boot_time);
        auto tm = *localtime(&boot_time_t);
        
        stringstream ss;
        ss << put_time(&tm, "%Y/%m/%d %H:%M:%S");
        return ss.str();
    }
    
    string format_size(uint64_t size) {
        vector<string> units = {"B", "K", "M", "G", "T", "P"};
        double size_d = static_cast<double>(size);
        int unit_index = 0;
        
        while (size_d >= 1024.0 && unit_index < (int)units.size() - 1) {
            size_d /= 1024.0;
            unit_index++;
        }
        
        stringstream ss;
        ss << fixed << setprecision(2) << size_d << " " << units[unit_index];
        return ss.str();
    }
    
    pair<uint64_t, uint64_t> get_memory() {
        #ifdef _WIN32
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        return {memInfo.ullTotalPhys, memInfo.ullTotalPhys - memInfo.ullAvailPhys};
        #else
        struct sysinfo info;
        sysinfo(&info);
        return {info.totalram * info.mem_unit, (info.freeram) * info.mem_unit};
        #endif
    }
    
    pair<uint64_t, uint64_t> get_swap() {
        #ifdef _WIN32
        return {0, 0};
        #else
        struct sysinfo info;
        sysinfo(&info);
        return {info.totalswap * info.mem_unit, (info.totalswap - info.freeswap) * info.mem_unit};
        #endif
    }
    
    pair<uint64_t, uint64_t> get_disk() {
        #ifdef _WIN32
        ULARGE_INTEGER totalBytes, freeBytes;
        if (GetDiskFreeSpaceEx(L"C:\\", &freeBytes, &totalBytes, nullptr)) {
            return {totalBytes.QuadPart, totalBytes.QuadPart - freeBytes.QuadPart};
        }
        return {0, 0};
        #else
        struct statvfs buffer;
        if (statvfs("/", &buffer) == 0) {
            uint64_t total = (uint64_t)buffer.f_blocks * buffer.f_frsize;
            uint64_t free = (uint64_t)buffer.f_bavail * buffer.f_frsize;
            return {total, total - free};
        }
        return {0, 0};
        #endif
    }
    
    pair<uint64_t, uint64_t> get_network() {
        #ifdef _WIN32
        return {0, 0};
        #else
        ifstream netdev("/proc/net/dev");
        string line;
        uint64_t total_rx = 0, total_tx = 0;
        
        while (getline(netdev, line)) {
            if (line.find(':') != string::npos && 
                line.find("lo") == string::npos &&
                line.find("docker") == string::npos) {
                
                stringstream ss(line);
                string interface;
                uint64_t rx_bytes, tx_bytes;
                string dummy;
                
                ss >> interface;
                ss >> rx_bytes;
                for (int i = 0; i < 7; i++) ss >> dummy;
                ss >> tx_bytes;
                
                total_rx += rx_bytes;
                total_tx += tx_bytes;
            }
        }
        return {total_rx, total_tx};
        #endif
    }
    
    tuple<int, int, int, int> get_tupd() {
        int tcp = 100, udp = 50, process = 200, thread = 800;
        
        #ifndef _WIN32
        FILE* fp;
        char result[128];
        
        fp = popen("ss -t | wc -l", "r");
        if (fp && fgets(result, sizeof(result), fp)) {
            tcp = max(0, atoi(result) - 1);
            pclose(fp);
        }
        
        fp = popen("ss -u | wc -l", "r");
        if (fp && fgets(result, sizeof(result), fp)) {
            udp = max(0, atoi(result) - 1);
            pclose(fp);
        }
        
        fp = popen("ps -ef | wc -l", "r");
        if (fp && fgets(result, sizeof(result), fp)) {
            process = max(0, atoi(result) - 2);
            pclose(fp);
        }
        
        fp = popen("ps -eLf | wc -l", "r");
        if (fp && fgets(result, sizeof(result), fp)) {
            thread = max(0, atoi(result) - 2);
            pclose(fp);
        }
        #endif
        
        return {tcp, udp, process, thread};
    }
    
    void ping_thread(const string& mark) {
        int lost_packet = 0;
        queue<int> packet_queue;
        const int max_history = 100;
        
        log_info("Starting ping thread for mark: " + mark);
        
        while (running) {
            string host;
            int port;
            
            {
                lock_guard<mutex> lock(ping_config_lock);
                auto it = ping_configs.find(mark);
                if (it != ping_configs.end()) {
                    host = it->second.host;
                    port = it->second.port;
                } else {
                    this_thread::sleep_for(chrono::seconds(2));
                    continue;
                }
            }
            
            auto start_time = chrono::high_resolution_clock::now();
            
            #ifdef _WIN32
            SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock != INVALID_SOCKET) {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                
                struct hostent* host_entry = gethostbyname(host.c_str());
                if (host_entry) {
                    memcpy(&addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
                    
                    DWORD timeout = 1000;
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
                    
                    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
                    auto end_time = chrono::high_resolution_clock::now();
                    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
                    
                    if (result == 0 || WSAGetLastError() == WSAECONNREFUSED) {
                        ping_times[mark] = static_cast<int>(duration.count());
                        packet_queue.push(1);
                    } else {
                        lost_packet++;
                        packet_queue.push(0);
                    }
                }
                closesocket(sock);
            }
            #else
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock >= 0) {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                
                struct hostent* host_entry = gethostbyname(host.c_str());
                if (host_entry) {
                    memcpy(&addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
                    
                    struct timeval timeout;
                    timeout.tv_sec = 1;
                    timeout.tv_usec = 0;
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                    
                    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
                    auto end_time = chrono::high_resolution_clock::now();
                    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
                    
                    if (result == 0 || errno == ECONNREFUSED) {
                        ping_times[mark] = static_cast<int>(duration.count());
                        packet_queue.push(1);
                    } else {
                        lost_packet++;
                        packet_queue.push(0);
                    }
                }
                close(sock);
            }
            #endif
            
            if (packet_queue.size() > max_history) {
                if (packet_queue.front() == 0) {
                    lost_packet--;
                }
                packet_queue.pop();
            }
            
            if (packet_queue.size() > 30) {
                lost_rates[mark] = static_cast<double>(lost_packet) / packet_queue.size();
            }
            
            this_thread::sleep_for(chrono::seconds(2));
        }
    }
    
    void net_speed_thread() {
        uint64_t last_rx = 0, last_tx = 0;
        auto last_time = chrono::high_resolution_clock::now();
        
        while (running) {
            auto [current_rx, current_tx] = get_network();
            auto current_time = chrono::high_resolution_clock::now();
            auto duration = chrono::duration_cast<chrono::seconds>(current_time - last_time).count();
            
            if (duration > 0 && last_rx > 0 && last_tx > 0) {
                net_speed["netrx"] = static_cast<double>(current_rx - last_rx) / duration;
                net_speed["nettx"] = static_cast<double>(current_tx - last_tx) / duration;
            }
            
            last_rx = current_rx;
            last_tx = current_tx;
            last_time = current_time;
            
            this_thread::sleep_for(chrono::seconds(1));
        }
    }
    
    void disk_io_thread() {
        #ifndef _WIN32
        uint64_t last_read = 0, last_write = 0;
        
        while (running) {
            ifstream diskstats("/proc/diskstats");
            string line;
            uint64_t total_read = 0, total_write = 0;
            
            while (getline(diskstats, line)) {
                stringstream ss(line);
                int major, minor;
                string device;
                uint64_t read_sectors, write_sectors;
                string dummy;
                
                ss >> major >> minor >> device;
                for (int i = 0; i < 2; i++) ss >> dummy;
                ss >> read_sectors;
                for (int i = 0; i < 3; i++) ss >> dummy;
                ss >> write_sectors;
                
                if (device.find("loop") == string::npos && device.find("ram") == string::npos) {
                    total_read += read_sectors * 512;
                    total_write += write_sectors * 512;
                }
            }
            
            if (last_read > 0 && last_write > 0) {
                disk_io["read"] = total_read - last_read;
                disk_io["write"] = total_write - last_write;
            }
            
            last_read = total_read;
            last_write = total_write;
            
            this_thread::sleep_for(chrono::seconds(1));
        }
        #endif
    }
    
    void docker_thread() {
        static map<string, DockerContainer> persistent_containers; // 持久化容器状态
        
        while (running) {
            try {
                lock_guard<mutex> lock(docker_lock);
                docker_dict.clear();
                
                // 检查Docker是否可用
                if (!check_docker_available()) {
                    this_thread::sleep_for(chrono::seconds(30));
                    continue;
                }
                
                // 获取所有容器的基本信息
                vector<DockerContainer> containers = get_docker_containers();
                
                // 合并新容器信息和历史状态
                for (auto& container : containers) {
                    // 如果容器已存在，保留其历史网络统计数据
                    if (persistent_containers.find(container.name) != persistent_containers.end()) {
                        DockerContainer& existing = persistent_containers[container.name];
                        // 只有当已存在有效的历史数据时才复制
                        auto time_since_epoch = existing.prev_time.time_since_epoch();
                        if (time_since_epoch.count() > 0) {
                            container.prev_rx_bytes = existing.prev_rx_bytes;
                            container.prev_tx_bytes = existing.prev_tx_bytes;
                            container.prev_time = existing.prev_time;
                            container.rx_speed = existing.rx_speed;
                            container.tx_speed = existing.tx_speed;
                        }
                    }
                    
                    if (container.status == "running") {
                        get_container_stats(container);
                    } else {
                        // 停止的容器网速为0
                        container.rx_speed = "0 B/s";
                        container.tx_speed = "0 B/s";
                    }
                    
                    // 更新持久化状态
                    persistent_containers[container.name] = container;
                    
                    // 转换为JSON格式存储
                    json container_json;
                    container_json["name"] = container.name;
                    container_json["status"] = container.status;
                    container_json["cpu_usage"] = container.cpu_usage;
                    container_json["memory_usage"] = container.memory_usage;
                    container_json["rx_speed"] = container.rx_speed;
                    container_json["tx_speed"] = container.tx_speed;
                    
                    docker_dict[container.name] = container_json;
                }
                
                // 清理不存在的容器
                for (auto it = persistent_containers.begin(); it != persistent_containers.end();) {
                    bool found = false;
                    for (const auto& container : containers) {
                        if (container.name == it->first) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        it = persistent_containers.erase(it);
                    } else {
                        ++it;
                    }
                }
                
            } catch (const exception& e) {
                log_info("Docker monitoring failed: " + string(e.what()));
            }
            
            this_thread::sleep_for(chrono::seconds(2));
        }
    }
    
    void start_realtime_data() {
        for (const auto& pair : ping_configs) {
            thread t(&ServerMonitor::ping_thread, this, pair.first);
            t.detach();
        }
        
        thread t1(&ServerMonitor::net_speed_thread, this);
        thread t2(&ServerMonitor::disk_io_thread, this);
        thread t3(&ServerMonitor::docker_thread, this);
        
        t1.detach();
        t2.detach();
        t3.detach();
    }
    
    void update_ping_target(const string& mark, const string& host, int port, const string& name) {
        if (!mark.empty() && !host.empty() && port > 0 && !name.empty()) {
            lock_guard<mutex> lock(ping_config_lock);
            ping_configs[mark] = {host, port, name};
            log_info("Updated " + mark + ": " + host + ":" + to_string(port) + " " + name);
        }
    }
    
    // 执行系统命令并获取输出
    string execute_command(const string& command) {
        string result;
        char buffer[128];
        
        #ifdef _WIN32
        FILE* pipe = _popen(command.c_str(), "r");
        #else
        FILE* pipe = popen(command.c_str(), "r");
        #endif
        
        if (!pipe) {
            return "";
        }
        
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        
        #ifdef _WIN32
        _pclose(pipe);
        #else
        pclose(pipe);
        #endif
        
        return result;
    }
    
    // 检查Docker是否可用
    bool check_docker_available() {
        string output = execute_command("docker --version 2>/dev/null");
        return !output.empty() && output.find("Docker") != string::npos;
    }
    
    // 获取所有Docker容器信息
    vector<DockerContainer> get_docker_containers() {
        vector<DockerContainer> containers;
        
        // 获取所有容器（包括停止的）
        string command = "docker ps -a --format \"{{.ID}}|{{.Names}}|{{.Status}}\"";
        string output = execute_command(command);
        
        if (output.empty()) {
            return containers;
        }
        
        // 解析输出
        stringstream ss(output);
        string line;
        
        while (getline(ss, line)) {
            if (line.empty()) continue;
            
            DockerContainer container;
            
            // 按|分割字段
            size_t pos1 = line.find('|');
            size_t pos2 = line.find('|', pos1 + 1);
            
            if (pos1 != string::npos && pos2 != string::npos) {
                container.id = line.substr(0, pos1);
                container.name = line.substr(pos1 + 1, pos2 - pos1 - 1);
                string status_full = line.substr(pos2 + 1);
                
                // 简化状态（Up -> running, Exited -> exited）
                if (status_full.find("Up") == 0) {
                    container.status = "running";
                } else if (status_full.find("Exited") == 0) {
                    container.status = "exited";
                } else {
                    container.status = "unknown";
                }
                
                container.prev_time = chrono::steady_clock::now();
                containers.push_back(container);
            }
        }
        
        return containers;
    }
    
    // 获取容器的详细统计信息
    void get_container_stats(DockerContainer& container) {
        try {
            // 获取容器统计信息（一次性采样）
            string command = "docker stats --no-stream --format \"{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}\" " + container.id;
            string output = execute_command(command);
            
            if (!output.empty()) {
                // 去除末尾的换行符
                if (!output.empty() && output.back() == '\n') {
                    output.pop_back();
                }
                
                // 解析统计信息
                size_t pos1 = output.find('|');
                size_t pos2 = output.find('|', pos1 + 1);
                
                if (pos1 != string::npos && pos2 != string::npos) {
                    container.cpu_usage = output.substr(0, pos1);
                    
                    // 解析内存使用情况
                    string mem_usage = output.substr(pos1 + 1, pos2 - pos1 - 1);
                    size_t slash_pos = mem_usage.find('/');
                    if (slash_pos != string::npos) {
                        container.memory_usage = mem_usage.substr(0, slash_pos);
                        // 去除空格
                        container.memory_usage.erase(remove(container.memory_usage.begin(), 
                                                          container.memory_usage.end(), ' '), 
                                                   container.memory_usage.end());
                    } else {
                        container.memory_usage = mem_usage;
                    }
                    
                    // 解析网络IO
                    string net_io = output.substr(pos2 + 1);
                    parse_network_io(container, net_io);
                }
            }
        } catch (const exception& e) {
            log_info("Failed to get stats for container " + container.name + ": " + e.what());
        }
    }
    
    // 解析网络IO并计算速度
    void parse_network_io(DockerContainer& container, const string& net_io) {
        try {
            // 网络IO格式通常是 "1.2kB / 2.3kB"（输入/输出）
            size_t slash_pos = net_io.find('/');
            if (slash_pos == string::npos) {
                container.rx_speed = "0 B";
                container.tx_speed = "0 B/s";
                return;
            }
            
            string rx_str = net_io.substr(0, slash_pos);
            string tx_str = net_io.substr(slash_pos + 1);
            
            // 去除空格
            rx_str.erase(remove(rx_str.begin(), rx_str.end(), ' '), rx_str.end());
            tx_str.erase(remove(tx_str.begin(), tx_str.end(), ' '), tx_str.end());
            
            uint64_t rx_bytes = parse_size_string(rx_str);
            uint64_t tx_bytes = parse_size_string(tx_str);
            
            auto current_time = chrono::steady_clock::now();
            
            // 检查是否是第一次采样（使用时间点判断更可靠）
            auto time_since_epoch = container.prev_time.time_since_epoch();
            bool is_first_sample = (time_since_epoch.count() == 0);
            
            if (is_first_sample) {
                container.prev_rx_bytes = rx_bytes;
                container.prev_tx_bytes = tx_bytes;
                container.prev_time = current_time;
                container.rx_speed = "0 B";
                container.tx_speed = "0 B/s";
                return;
            }
            auto time_diff = chrono::duration_cast<chrono::seconds>(current_time - container.prev_time).count();
            // 确保时间间隔合理（至少1秒）
            if (time_diff >= 1) {
                uint64_t rx_speed = 0;
                uint64_t tx_speed = 0;
                
                // 计算速度（字节/秒）
                if (rx_bytes >= container.prev_rx_bytes) {
                    rx_speed = (rx_bytes - container.prev_rx_bytes) / time_diff;
                }
                if (tx_bytes >= container.prev_tx_bytes) {
                    tx_speed = (tx_bytes - container.prev_tx_bytes) / time_diff;
                }
                
                container.rx_speed = format_size(rx_speed);
                container.tx_speed = format_size(tx_speed) + "/s";
                // 更新历史数据
                container.prev_rx_bytes = rx_bytes;
                container.prev_tx_bytes = tx_bytes;
                container.prev_time = current_time;
            } else {
                log_info("Container " + container.name + ": Time interval too short, keeping previous speed");
            }
            
        } catch (const exception& e) {
            container.rx_speed = "null";
            container.tx_speed = "null";
            log_info("Container " + container.name + ": Parse error - " + string(e.what()));
        }
    }
    
    // 解析大小字符串（如"1.2kB", "3.4MB"）到字节数
    uint64_t parse_size_string(const string& size_str) {
        if (size_str.empty()) return 0;
        
        string num_str;
        string unit_str;
        
        // 分离数字和单位
        size_t i = 0;
        while (i < size_str.length() && (isdigit(size_str[i]) || size_str[i] == '.')) {
            num_str += size_str[i];
            i++;
        }
        
        while (i < size_str.length()) {
            unit_str += size_str[i];
            i++;
        }
        
        if (num_str.empty()) return 0;
        
        double value = stod(num_str);
        
        // 转换单位
        if (unit_str == "B" || unit_str.empty()) {
            return static_cast<uint64_t>(value);
        } else if (unit_str == "kB" || unit_str == "KB") {
            return static_cast<uint64_t>(value * 1000);
        } else if (unit_str == "MB") {
            return static_cast<uint64_t>(value * 1000 * 1000);
        } else if (unit_str == "GB") {
            return static_cast<uint64_t>(value * 1000 * 1000 * 1000);
        } else if (unit_str == "KiB") {
            return static_cast<uint64_t>(value * 1024);
        } else if (unit_str == "MiB") {
            return static_cast<uint64_t>(value * 1024 * 1024);
        } else if (unit_str == "GiB") {
            return static_cast<uint64_t>(value * 1024 * 1024 * 1024);
        }
        
        return static_cast<uint64_t>(value);
    }
    
    void monitor_vps() {
        while (running) {
            try {
                log_info("Connecting to server...");
                
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) {
                    log_info("Failed to create socket");
                    this_thread::sleep_for(chrono::seconds(30));
                    continue;
                }
                
                struct sockaddr_in server_addr;
                server_addr.sin_family = AF_INET;
                server_addr.sin_port = htons(server_port);
                inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);
                
                if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                    log_info("Failed to connect to server");
                    close(sock);
                    this_thread::sleep_for(chrono::seconds(30));
                    continue;
                }
                
                // 优化socket缓冲区和选项设置以提高大包传输可靠性
                int send_buffer_size = 65536;  // 64KB发送缓冲区
                int recv_buffer_size = 32768;  // 32KB接收缓冲区
                setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size));
                setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recv_buffer_size, sizeof(recv_buffer_size));
                
                // 启用TCP_NODELAY以减少延迟
                int flag = 1;
                setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
                
                // 启用保活机制
                int keepalive = 1;
                setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
                
                char buffer[1024];
                int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (bytes_received > 0) {
                    buffer[bytes_received] = '\0';
                    string response(buffer);
                    
                    if (response.find("Authentication required") != string::npos) {
                        json auth_data;
                        auth_data["Authentication"] = client_id;
                        auth_data["vps_ip"] = ipv4 + "," + ipv6;
                        
                        string auth_str = auth_data.dump();
                        send(sock, auth_str.c_str(), auth_str.length(), 0);
                        
                        bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                        if (bytes_received > 0) {
                            buffer[bytes_received] = '\0';
                            string auth_response(buffer);
                            if (auth_response.find("Authentication successful") == string::npos) {
                                log_info("Authentication failed: " + auth_response);
                                close(sock);
                                this_thread::sleep_for(chrono::seconds(30));
                                continue;
                            }
                        }
                    }
                }
                
                string get_arg = "get arg";
                send(sock, get_arg.c_str(), get_arg.length(), 0);
                
                bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (bytes_received > 0) {
                    buffer[bytes_received] = '\0';
                    string arg_response(buffer);
                    
                    if (arg_response.find("arg") != string::npos) {
                        string arg_succ = "arg succ";
                        send(sock, arg_succ.c_str(), arg_succ.length(), 0);
                        
                        try {
                            // 使用简化的字段解析函数解析初始配置
                            string cu_ip = parse_json_field(arg_response, "cu_ip");
                            string cu_port_str = parse_json_field(arg_response, "cu_port");
                            string cu_name = decode_unicode_escapes(parse_json_field(arg_response, "cu_name"));
                            
                            string ct_ip = parse_json_field(arg_response, "ct_ip");
                            string ct_port_str = parse_json_field(arg_response, "ct_port");
                            string ct_name = decode_unicode_escapes(parse_json_field(arg_response, "ct_name"));
                            
                            string cm_ip = parse_json_field(arg_response, "cm_ip");
                            string cm_port_str = parse_json_field(arg_response, "cm_port");
                            string cm_name = decode_unicode_escapes(parse_json_field(arg_response, "cm_name"));
                            
                            // 更新ping目标并记录日志
                            if (!cu_ip.empty() && !cu_port_str.empty() && !cu_name.empty()) {
                                update_ping_target("10010", cu_ip, stoi(cu_port_str), cu_name);
                                log_info("Configured CU: " + cu_name + " (" + cu_ip + ":" + cu_port_str + ")");
                            }
                            if (!ct_ip.empty() && !ct_port_str.empty() && !ct_name.empty()) {
                                update_ping_target("189", ct_ip, stoi(ct_port_str), ct_name);
                                log_info("Configured CT: " + ct_name + " (" + ct_ip + ":" + ct_port_str + ")");
                            }
                            if (!cm_ip.empty() && !cm_port_str.empty() && !cm_name.empty()) {
                                update_ping_target("10086", cm_ip, stoi(cm_port_str), cm_name);
                                log_info("Configured CM: " + cm_name + " (" + cm_ip + ":" + cm_port_str + ")");
                            }
                            
                            if (!threading_start) {
                                start_realtime_data();
                                threading_start = true;
                                log_info("Started monitoring threads");
                            }
                        } catch (const exception& e) {
                            log_info("Failed to parse config: " + string(e.what()));
                        }
                    }
                }
                
                while (running) {
                    try {
                        json data;
                        
                        data["version"] = "2.0.0";
                        data["uuid"] = uuid;
                        data["client_id"] = client_id;
                        data["priority"] = priority;
                        data["country_code"] = country_code;
                        
                        // 修复emoji JSON解析错误 - 直接使用JSON字符串
                        try {
                            if (!emoji.empty() && emoji != "\"\"" && emoji != "{}") {
                                data["emoji"] = json::parse(emoji);
                            } else {
                                data["emoji"] = json::object(); // 使用空JSON对象
                                log_info("DEBUG: Using empty emoji object (emoji=" + emoji + ")");
                            }
                        } catch (const exception& e) {
                            log_info("Failed to parse emoji JSON, using empty object: " + string(e.what()));
                            data["emoji"] = json::object(); // 使用空JSON对象
                        }
                        
                        data["ipv4"] = ipv4;
                        data["ipv6"] = ipv6;

                        try {
                            data["server_uptime"] = get_uptime();
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get uptime: " + string(e.what()));
                            data["server_uptime"] = "0";
                        }
                        
                        try {
                            data["system_version"] = get_system_version();
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get system version: " + string(e.what()));
                            data["system_version"] = "Unknown";
                        }
                        
                        try {
                            data["cpu_model"] = get_cpu_model();
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get CPU model: " + string(e.what()));
                            data["cpu_model"] = "Unknown";
                        }
                        
                        try {
                            data["cpu_usage"] = get_cpu_usage();
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get CPU usage: " + string(e.what()));
                            data["cpu_usage"] = vector<int>{0};
                        }
                        
                        try {
                            auto [disk_total, disk_used] = get_disk();
                            data["disk_total_size"] = format_size(disk_total);
                            data["disk_used_size"] = format_size(disk_used);
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get disk info: " + string(e.what()));
                            data["disk_total_size"] = "0B";
                            data["disk_used_size"] = "0B";
                        }
                        
                        try {
                            auto [memory_total, memory_used] = get_memory();
                            data["memory_total_size"] = format_size(memory_total);
                            data["memory_used_size"] = format_size(memory_used);
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get memory info: " + string(e.what()));
                            data["memory_total_size"] = "0B";
                            data["memory_used_size"] = "0B";
                        }
                        
                        try {
                            auto [swap_total, swap_used] = get_swap();
                            data["swap_total_size"] = format_size(swap_total);
                            data["swap_used_size"] = format_size(swap_used);
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get swap info: " + string(e.what()));
                            data["swap_total_size"] = "0B";
                            data["swap_used_size"] = "0B";
                        }
                        
                        try {
                            auto [network_in, network_out] = get_network();
                            data["network_upload_size"] = format_size(network_out);
                            data["network_download_size"] = format_size(network_in);
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get network stats: " + string(e.what()));
                            data["network_upload_size"] = "0B";
                            data["network_download_size"] = "0B";
                        }
                        
                        data["network_rx"] = format_size(static_cast<uint64_t>(net_speed["netrx"]));
                        data["network_tx"] = format_size(static_cast<uint64_t>(net_speed["nettx"]));
                        
                        try {
                            auto load_avg = get_load_average();
                            stringstream load_ss;
                            load_ss << fixed << setprecision(2) << load_avg[0] << "," << load_avg[1] << "," << load_avg[2];
                            data["load_averages"] = load_ss.str();
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get load averages: " + string(e.what()));
                            data["load_averages"] = "0.00,0.00,0.00";
                        }
                        
                        try {
                            auto [tcp, udp, process, thread] = get_tupd();
                            data["tcp"] = tcp;
                            data["udp"] = udp;
                            data["process"] = process;
                            data["thread"] = thread;
                        } catch (const exception& e) {
                            log_info("DEBUG: Failed to get connection counts: " + string(e.what()));
                            data["tcp"] = 0;
                            data["udp"] = 0;
                            data["process"] = 0;
                            data["thread"] = 0;
                        }
                        
                        data["io_read"] = format_size(disk_io["read"]);
                        data["io_write"] = format_size(disk_io["write"]);
                        
                        {
                            lock_guard<mutex> lock(docker_lock);
                            data["dockers"] = docker_dict;
                        }
                        
                        {
                            lock_guard<mutex> lock(ping_config_lock);
                            data["name_10010"] = ping_configs["10010"].name;
                            data["name_189"] = ping_configs["189"].name;
                            data["name_10086"] = ping_configs["10086"].name;
                        }
                        
                        data["ping_10010"] = lost_rates["10010"] * 100;
                        data["ping_189"] = lost_rates["189"] * 100;
                        data["ping_10086"] = lost_rates["10086"] * 100;
                        data["time_10010"] = ping_times["10010"];
                        data["time_189"] = ping_times["189"];
                        data["time_10086"] = ping_times["10086"];
                        
                        string json_str = "update:" + data.dump() + "`";
                        // 可靠发送数据包 - 增强版本
                        size_t total_sent = 0;
                        size_t data_length = json_str.length();
                        const char* data_ptr = json_str.c_str();
                        int retry_count = 0;
                        const int max_retries = 3;
                        bool send_success = false;
                        
                        while (retry_count < max_retries && !send_success) {
                            total_sent = 0;
                            bool current_attempt_success = true;
                            while (total_sent < data_length && current_attempt_success) {
                                // 设置发送超时
                                struct timeval tv;
                                tv.tv_sec = 5;  // 5秒超时
                                tv.tv_usec = 0;
                                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
                                
                                // 分块发送，每次最多发送4096字节
                                size_t chunk_size = min((size_t)4096, data_length - total_sent);
                                int sent_bytes = send(sock, data_ptr + total_sent, chunk_size, 0);
                                
                                if (sent_bytes < 0) {
                                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                        this_thread::sleep_for(chrono::milliseconds(10));
                                        continue;
                                    } else {
                                        log_info("DEBUG: Failed to send data packet, error: " + to_string(errno) + " (" + strerror(errno) + ")");
                                        current_attempt_success = false;
                                        break;
                                    }
                                } else if (sent_bytes == 0) {
                                    current_attempt_success = false;
                                    break;
                                } else {
                                    total_sent += sent_bytes;
                                    
                                    // 添加小延迟以避免网络拥塞
                                    if (total_sent < data_length) {
                                        this_thread::sleep_for(chrono::microseconds(100));
                                    }
                                }
                            }
                            
                            if (current_attempt_success && total_sent == data_length) {
                                send_success = true;
                                
                                // 确保数据真正发送到网络
                                int flag = 1;
                                setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
                                
                            } else {
                                retry_count++;
                                if (retry_count < max_retries) {
                                    this_thread::sleep_for(chrono::milliseconds(100));
                                }
                            }
                        }
                        
                        if (!send_success) {
                            log_info("DEBUG: Failed to send complete data packet after " + to_string(max_retries) + " attempts");
                            break;
                        }
                        
                        this_thread::sleep_for(chrono::seconds(1));
                        
                        fd_set readfds;
                        FD_ZERO(&readfds);
                        FD_SET(sock, &readfds);
                        
                        struct timeval timeout;
                        timeout.tv_sec = 0;
                        timeout.tv_usec = 100000;
                        
                        int activity = select(sock + 1, &readfds, nullptr, nullptr, &timeout);
                        if (activity > 0 && FD_ISSET(sock, &readfds)) {
                            bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                            if (bytes_received > 0) {
                                buffer[bytes_received] = '\0';
                                string server_data(buffer);
                                log_info("Received from server: " + server_data);
                                
                                if (server_data.find("arg") != string::npos && server_data.find("update_ping") != string::npos) {
                                    try {
                                        // 使用简化的字段解析函数
                                        string cu_ip = parse_json_field(server_data, "cu_ip");
                                        string cu_port_str = parse_json_field(server_data, "cu_port");
                                        string cu_name = decode_unicode_escapes(parse_json_field(server_data, "cu_name"));
                                        
                                        string ct_ip = parse_json_field(server_data, "ct_ip");
                                        string ct_port_str = parse_json_field(server_data, "ct_port");
                                        string ct_name = decode_unicode_escapes(parse_json_field(server_data, "ct_name"));
                                        
                                        string cm_ip = parse_json_field(server_data, "cm_ip");
                                        string cm_port_str = parse_json_field(server_data, "cm_port");
                                        string cm_name = decode_unicode_escapes(parse_json_field(server_data, "cm_name"));
                                        
                                        // 更新所有ping目标
                                        if (!cu_ip.empty() && !cu_port_str.empty()) {
                                            update_ping_target("10010", cu_ip, stoi(cu_port_str), cu_name);
                                            log_info("Updated ping target CU: " + cu_name + " (" + cu_ip + ":" + cu_port_str + ")");
                                        }
                                        if (!ct_ip.empty() && !ct_port_str.empty()) {
                                            update_ping_target("189", ct_ip, stoi(ct_port_str), ct_name);
                                            log_info("Updated ping target CT: " + ct_name + " (" + ct_ip + ":" + ct_port_str + ")");
                                        }
                                        if (!cm_ip.empty() && !cm_port_str.empty()) {
                                            update_ping_target("10086", cm_ip, stoi(cm_port_str), cm_name);
                                            log_info("Updated ping target CM: " + cm_name + " (" + cm_ip + ":" + cm_port_str + ")");
                                        }
                                    } catch (const exception& e) {
                                        log_info("Failed to parse update request: " + string(e.what()));
                                    }
                                }
                            } else if (bytes_received == 0) {
                                log_info("Server closed connection");
                                break;
                            }
                        }
                    } catch (const exception& e) {
                        log_info("Exception in monitor_vps: " + string(e.what()));
                    }
                }
                
                close(sock);
                
            } catch (const exception& e) {
                log_info("Exception in monitor_vps: " + string(e.what()));
            }
            
            log_info("Disconnected... Retrying in 3 seconds");
            this_thread::sleep_for(chrono::seconds(3));
        }
    }
    
    void start() {
        get_client_ip();
        auto [server, port] = get_server_ip();
        
        if (server.empty() || port == 0) {
            log_info("Failed to get server IP and port after all retries");
            log_info("Program will exit. Please check network connection and server URL.");
            return;
        }
        
        server_ip = server;
        server_port = port;
        
        log_info("Starting monitor with server: " + server_ip + ":" + to_string(server_port));
        
        thread monitor_thread(&ServerMonitor::monitor_vps, this);
        
        while (running) {
            this_thread::sleep_for(chrono::hours(6));
            
            string old_priority = priority;
            string old_country = country_code;
            string old_emoji = emoji;
            string old_ipv4 = ipv4;
            string old_ipv6 = ipv6;
            
            get_client_ip();
            
            if (!priority.empty() || !country_code.empty() || !emoji.empty() || !ipv4.empty() || !ipv6.empty()) {
                log_info("IP address updated successfully");
            } else {
                priority = old_priority;
                country_code = old_country;
                emoji = old_emoji;
                ipv4 = old_ipv4;
                ipv6 = old_ipv6;
                log_info("IP address update failed, using cached values");
            }
            
            // 定期尝试更新服务器IP和端口信息
            log_info("Checking for server IP updates...");
            auto [new_server, new_port] = get_server_ip_with_retry(3, 30); // 3次重试，间隔30秒
            if (!new_server.empty() && new_port > 0) {
                if (new_server != server_ip || new_port != server_port) {
                    log_info("Server IP/Port changed from " + server_ip + ":" + to_string(server_port) + 
                            " to " + new_server + ":" + to_string(new_port));
                    server_ip = new_server;
                    server_port = new_port;
                }
            } else {
                log_info("Failed to update server IP, keeping current: " + server_ip + ":" + to_string(server_port));
            }
        }
        
        monitor_thread.join();
    }
    
    void stop() {
        running = false;
    }
};

ServerMonitor* global_monitor = nullptr;

void signal_handler(int /* signal */) {
    cout << "\nReceived interrupt signal, shutting down..." << endl;
    if (global_monitor) {
        global_monitor->stop();
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    string uuid, client_id, url;
    
    for (int i = 1; i < argc; i++) {
        string arg(argv[i]);
        if (arg.find("UUID=") == 0) {
            uuid = arg.substr(5);
        } else if (arg.find("Client_ID=") == 0) {
            client_id = arg.substr(10);
        } else if (arg.find("URL=") == 0) {
            url = arg.substr(4);
        }
    }
    
    if (uuid.empty() || client_id.empty() || url.empty()) {
        cout << "Usage: " << argv[0] << " UUID=<uuid> Client_ID=<client_id> URL=<url>" << endl;
        return 1;
    }
    
    ServerMonitor monitor(uuid, client_id, url);
    global_monitor = &monitor;
    
    signal(SIGINT, signal_handler);
    
    monitor.start();
    
    return 0;
} 