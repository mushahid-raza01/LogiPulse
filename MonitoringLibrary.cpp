#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <string>
#include <ctime>
#include <stdexcept>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <thread>
#include <random>
#include <boost/json.hpp> // Include Boost.JSON for JSON handling
#include <boost/asio.hpp>
#include <boost/chrono.hpp>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#else
#include <dirent.h>
#include <cstring>
#include <csignal>
#include <unistd.h>
#endif

namespace json = boost::json;

namespace beast = boost::beast;
namespace http = beast::http;
namespace pt = boost::property_tree;
namespace asio = boost::asio;
using boost::asio::ip::tcp;
namespace json = boost::json;

extern "C" {
    std::string global_string = {};
    //class APIServer {
    //public:
    //    APIServer(boost::asio::io_context& io_context, unsigned short port)
    //        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), m_io_context(io_context){
    //        start_accept();
    //    }
    //
    //private:
    //    void start_accept() {
    //        //boost::asio::io_context io_context;
    //        auto executor = m_io_context.get_executor(); // This should work in C++17 or later
    //        auto socket = std::make_shared<tcp::socket>(executor.context());
    //        acceptor_.async_accept(*socket, [this, socket](const boost::system::error_code& error) {
    //            if (!error) {
    //                handle_request(socket);
    //            }
    //            start_accept();
    //            });
    //    }
    //
    //    void handle_request(std::shared_ptr<tcp::socket> socket) {
    //        auto buffer = std::make_shared<boost::asio::streambuf>();
    //
    //        boost::asio::async_read_until(*socket, *buffer, "\r\n\r\n",
    //            [this, socket, buffer](const boost::system::error_code& error, std::size_t bytes_transferred) {
    //                if (!error) {
    //                    std::istream stream(buffer.get());
    //                    std::string request_line;
    //                    std::getline(stream, request_line);
    //
    //                    // Skip headers (not used here)
    //                    std::string header;
    //                    while (std::getline(stream, header) && header != "\r") {}
    //
    //                    // Read and process JSON payload
    //                    std::ostringstream payload_stream;
    //                    payload_stream << stream.rdbuf();
    //                    std::string payload = payload_stream.str();
    //
    //                    try {
    //                        // Parse JSON payload
    //                        json::value json_payload = json::parse(payload);
    //
    //                        // Generate JSON response
    //                        json::object response_json;
    //                        response_json["status"] = "success";
    //                        response_json["received"] = json_payload;
    //                        std::string response_body = json::serialize(response_json);
    //
    //                        // Send response
    //                        send_response(socket, response_body);
    //                    }
    //                    catch (const std::exception& e) {
    //                        // Handle invalid JSON
    //                        send_response(socket, R"({"status": "error", "message": "Invalid JSON"})");
    //                    }
    //                }
    //            });
    //    }
    //
    //    void send_response(std::shared_ptr<tcp::socket> socket, const std::string& response_body) {
    //        std::ostringstream response_stream;
    //        response_stream << "HTTP/1.1 200 OK\r\n";
    //        response_stream << "Content-Type: application/json\r\n";
    //        response_stream << "Content-Length: " << response_body.size() << "\r\n";
    //        response_stream << "\r\n";
    //        response_stream << response_body;
    //
    //        boost::asio::async_write(*socket, boost::asio::buffer(response_stream.str()),
    //            [socket](const boost::system::error_code& error, std::size_t) {
    //                socket->shutdown(tcp::socket::shutdown_both);
    //                socket->close();
    //            });
    //    }
    //
    //    tcp::acceptor acceptor_;
    //    boost::asio::io_context& m_io_context;
    //};


    //std::string metricsToJson(const ServiceMetrics& metrics) {
    //    std::ostringstream oss;
    //    pt::write_json(oss, metrics.toPropertyTree(), false); // Disable pretty printing
    //    return oss.str();
    //}

std::string measure_api_performance(const std::string& host, const std::string& target, int num_requests,int port = 80)
{
    namespace beast = boost::beast;         // from <boost/beast.hpp>
    namespace http = beast::http;           // from <boost/beast/http.hpp>
    namespace net = boost::asio;            // from <boost/asio.hpp>
    using tcp = net::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
    std::string response = "";
    int failure_count = 0;
    boost::chrono::duration<double> duration;
    double throughput;
    try
    {
        // Set up an I/O context and a resolver
        net::io_context ioc;
        tcp::resolver resolver(ioc);
        tcp::socket socket(ioc);
 
        // Resolve the domain name and connect to the server
        auto const results = resolver.resolve(host, std::to_string(port));
        net::connect(socket, results.begin(), results.end());
 
        // Set up the request
        http::request<http::string_body> req{ http::verb::get, target, 11 };
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
 
        // Start measuring time
        auto start_time = boost::chrono::high_resolution_clock::now();
 
        // Send the request and receive responses num_requests times
        for (int i = 0; i < num_requests; ++i)
        {
            http::write(socket, req);
 
            // Prepare the response
            beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
 
            // Receive the HTTP response
            http::read(socket, buffer, res);
 
            // You can process the response here
        }
 
        // Stop measuring time
        auto end_time = boost::chrono::high_resolution_clock::now();
        duration = end_time - start_time;
 
        // Calculate throughput (requests per second)
        throughput = num_requests / duration.count();
 
        //std::cout << "Performed " << num_requests << " requests in " << duration.count() << " seconds." << std::endl;
        //std::cout << "Throughput: " << throughput << " requests per second." << std::endl;

        // Close the socket
        socket.shutdown(tcp::socket::shutdown_both);
    }
    catch (std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        failure_count++;
    }

    response = "{";
    response += "\"api_name\": " + target + ", ";
    response += "\"num_requests\": " + std::to_string(num_requests) + ", ";
    response += "\"duration_count\": " + std::to_string(duration.count()) + ", ";
    response += "\"throughput\": " + std::to_string(throughput) + ", ";
    response += "\"failure_count\": " + std::to_string(failure_count);
    response += "}";

    global_string = response;
    return response;
 
 
}


    std::string mergeJsonStrings(const std::string& jsonString1, const std::string& key1,
        const std::string& jsonString2, const std::string& key2) {
        try {
            // Parse the JSON strings
            json::value value1 = json::parse(jsonString1);
            json::value value2 = json::parse(jsonString2);

            // Create a new JSON object
            json::object mergedJson;

            // Add the parsed JSON objects under specified keys
            mergedJson[key1] = value1.as_object();
            mergedJson[key2] = value2.as_object();

            // Serialize the merged JSON object to a string
            return json::serialize(mergedJson);
        }
        catch (const std::exception& e) {
            // Handle any parsing or runtime errors
            return std::string("Error merging JSON strings: ") + e.what();
        }
    }

    struct ServiceMetrics {
        int pid = 0;
        std::string name;
        double cpuPercent = 0.0;
        double memoryPercent = 0.0;
        size_t memoryUsage = 0;
        std::string status;
        int numThreads = 0;
        time_t createTime = 0;
    };

    // To convert ServiceMetrics to JSON
    boost::json::object to_json(const ServiceMetrics& metrics) {
        boost::json::object j;
        j["pid"] = metrics.pid;
        j["name"] = metrics.name;
        j["cpuPercent"] = metrics.cpuPercent;
        j["memoryPercent"] = metrics.memoryPercent;
        j["memoryUsage"] = metrics.memoryUsage;
        j["status"] = metrics.status;
        j["numThreads"] = metrics.numThreads;
        j["createTime"] = metrics.createTime;
        return j;
    }

    // To convert JSON to ServiceMetrics
    ServiceMetrics from_json(const boost::json::object& j) {
        ServiceMetrics metrics;
        metrics.pid = boost::json::value_to<int>(j.at("pid"));
        metrics.name = boost::json::value_to<std::string>(j.at("name"));
        metrics.cpuPercent = boost::json::value_to<double>(j.at("cpuPercent"));
        metrics.memoryPercent = boost::json::value_to<double>(j.at("memoryPercent"));
        metrics.memoryUsage = boost::json::value_to<size_t>(j.at("memoryUsage"));
        metrics.status = boost::json::value_to<std::string>(j.at("status"));
        metrics.numThreads = boost::json::value_to<int>(j.at("numThreads"));
        metrics.createTime = boost::json::value_to<time_t>(j.at("createTime"));
        return metrics;
    }


    double getTotalCpuTime() {
#ifdef _WIN32
        FILETIME idleTime, kernelTime, userTime;
        if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER kernel, user;
            kernel.LowPart = kernelTime.dwLowDateTime;
            kernel.HighPart = kernelTime.dwHighDateTime;
            user.LowPart = userTime.dwLowDateTime;
            user.HighPart = userTime.dwHighDateTime;
            return (kernel.QuadPart + user.QuadPart) / 10000000.0; // Convert to seconds
        }
        return 0.0;
#else
        std::ifstream statFile("/proc/stat");
        std::string line;
        getline(statFile, line);
        std::istringstream iss(line);
        std::string temp;
        iss >> temp;
        long long total = 0, value;
        while (iss >> value) total += value;
        return total / sysconf(_SC_CLK_TCK);
#endif
    }

    double getTotalSystemMemory() {
#ifdef _WIN32
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memStatus)) {
            return static_cast<double>(memStatus.ullTotalPhys);
        }
        return 0.0;
#else
        std::ifstream meminfo("/proc/meminfo");
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.substr(0, 9) == "MemTotal:") {
                std::istringstream iss(line.substr(10));
                long long memTotal;
                iss >> memTotal;
                return memTotal * 1024; // Convert kB to bytes
            }
        }
        return 0.0;
#endif
    }

#ifdef _WIN32
    ServiceMetrics getWindowsServiceMetrics(const std::string& serviceName) {
        ServiceMetrics metrics = {};
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            std::cerr << "Failed to open Service Control Manager. Error: " << GetLastError() << std::endl;
            return metrics;
        }

        std::wstring serviceName_(serviceName.begin(), serviceName.end());
        SC_HANDLE hService = OpenService(hSCManager, serviceName_.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        if (!hService) {
            std::cerr << "Failed to open service: " << serviceName << ". Error: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return metrics;
        }

        SERVICE_STATUS_PROCESS serviceStatus;
        DWORD bytesNeeded = 0;
        if (!QueryServiceStatusEx(
            hService,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&serviceStatus),
            sizeof(serviceStatus),
            &bytesNeeded)) {
            std::cerr << "Failed to query service status for: " << serviceName << ". Error: " << GetLastError() << std::endl;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return metrics;
        }

        metrics.pid = serviceStatus.dwProcessId;
        metrics.name = serviceName;

        if (metrics.pid > 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, metrics.pid);
            if (hProcess) {
                FILETIME creationTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
                    ULARGE_INTEGER kernel, user;
                    kernel.LowPart = kernelTime.dwLowDateTime;
                    kernel.HighPart = kernelTime.dwHighDateTime;
                    user.LowPart = userTime.dwLowDateTime;
                    user.HighPart = userTime.dwHighDateTime;

                    metrics.cpuPercent = (kernel.QuadPart + user.QuadPart) / 10000.0; // Convert to milliseconds
                    metrics.cpuPercent = (metrics.cpuPercent / getTotalCpuTime()) * 100;
                }

                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    metrics.memoryUsage = pmc.WorkingSetSize;
                    metrics.memoryPercent = (static_cast<double>(pmc.WorkingSetSize) / static_cast<double>(getTotalSystemMemory())) * 100.0;
                    DWORD threadCountWin;
                    if (!GetProcessHandleCount(hProcess, &threadCountWin)) {
                        metrics.numThreads = -1;
                    }
                    else {
                        metrics.numThreads = static_cast<int>(threadCountWin);
                    }
                }
                else {
                    std::cerr << "Failed to retrieve memory info for PID: " << metrics.pid << ". Error: " << GetLastError() << std::endl;
                }

                CloseHandle(hProcess);
            }
            else {
                std::cerr << "Failed to open process for PID: " << metrics.pid << ". Error: " << GetLastError() << std::endl;
            }
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return metrics;
    }
#else
    int getServicePid(const std::string& serviceName) {
        std::string command = "systemctl show -p MainPID --value " + serviceName + " 2>/dev/null";
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) {
            std::cerr << "Failed to query service status for: " << serviceName << std::endl;
            return 0;
        }

        char buffer[128];
        std::string result;
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);

        try {
            return std::stoi(result);
        }
        catch (...) {
            return 0;
        }
    }

    ServiceMetrics getLinuxServiceMetrics(const std::string& serviceName) {
        ServiceMetrics metrics = {};
        int pid = getServicePid(serviceName);
        if (pid == 0) {
            std::cerr << "Service not found or not running: " << serviceName << std::endl;
            return metrics;
        }

        metrics.pid = pid;
        metrics.name = serviceName;

        std::string statPath = "/proc/" + std::to_string(pid) + "/stat";
        std::ifstream statFile(statPath);
        if (statFile) {
            std::string line;
            std::getline(statFile, line);
            std::istringstream ss(line);

            std::string temp;
            long utime, stime;
            for (int i = 0; i < 13; ++i) ss >> temp; // Skip fields
            ss >> utime >> stime;

            double cpuTime = (utime + stime) / static_cast<double>(sysconf(_SC_CLK_TCK));
            metrics.cpuPercent = cpuTime;

            size_t rssPages;
            ss >> rssPages;
            metrics.memoryUsage = rssPages * sysconf(_SC_PAGESIZE);
            metrics.memoryPercent = (static_cast<double>(metrics.memoryUsage) / static_cast<double>(getTotalSystemMemory())) * 100.0;
        }

        return metrics;
    }
#endif

    bool isResourceThresholdExceeded(const ServiceMetrics& metrics, double cpuThreshold, size_t memoryThreshold, double totalCpuTime) {
        return metrics.cpuPercent > cpuThreshold || metrics.memoryPercent > memoryThreshold;
    }
    static bool monitor_thread = false;
    void monitorServices(const std::vector<std::string>& serviceNames, double cpuThreshold, size_t memoryThreshold, int delaySeconds) {
        std::cout << "Starting Monitoring" << std::endl;
        while (monitor_thread) 
        {
            for (const auto& serviceName : serviceNames) 
            {
#ifdef _WIN32
                ServiceMetrics metrics = getWindowsServiceMetrics(serviceName);
#else
                ServiceMetrics metrics = getLinuxServiceMetrics(serviceName);
#endif
                double totalCpuTime = getTotalCpuTime();
                double totalMemory = getTotalSystemMemory();

                std::cout << "Service Metrics for " << metrics.name << ":" << std::endl;
                std::cout << "PID: " << metrics.pid << std::endl;
                std::cout << "CPU Usage (%): " << std::fixed << std::setprecision(2) << metrics.cpuPercent << std::endl;
                std::cout << "Memory Usage (%): " << std::fixed << std::setprecision(2) << metrics.memoryPercent << std::endl;
                std::cout << "Memory Usage (MB): " << metrics.memoryUsage / (1024.0 * 1024.0) << std::endl;
                std::cout << "Threads: " << metrics.numThreads << std::endl;

                if (isResourceThresholdExceeded(metrics, cpuThreshold, memoryThreshold, totalCpuTime)) {
                    std::cerr << "Resource threshold exceeded for service: " << metrics.name << std::endl;
                }

                std::cout << "===================================" << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::seconds(delaySeconds));
        }
    }

    // Function to check if a service is running
    bool isServiceRunning(const std::string& serviceName) {
#ifdef _WIN32
        std::string command = "sc query " + serviceName + " | findstr /i \"RUNNING\" > nul";
        return (system(command.c_str()) == 0);
#else
        std::string command = "systemctl is-active --quiet " + serviceName;
        return (system(command.c_str()) == 0);
#endif
    }

    // Function to get the process start time and calculate uptime
    std::string getServiceUptime(const std::string& serviceName) {
#ifdef _WIN32
        // Open a handle to the service
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            return "Unable to open Service Control Manager";
        }

        std::wstring serviceName_(serviceName.begin(), serviceName.end()); // Convert to std::string
        SC_HANDLE hService = OpenService(hSCManager, serviceName_.c_str(), SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return "Service not found or access denied";
        }

        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded;
        if (!QueryServiceStatusEx(
            hService,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp),
            sizeof(SERVICE_STATUS_PROCESS),
            &bytesNeeded)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return "Failed to query service status";
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);

        // Calculate uptime
        ULONGLONG currentTime = GetTickCount64();
        ULONGLONG uptimeMillis = currentTime - ssp.dwCheckPoint;
        ULONGLONG uptimeSeconds = uptimeMillis / 1000;

        std::ostringstream oss;
        oss << uptimeSeconds << " seconds";
        return oss.str();
#else
        // Linux-specific implementation
        std::string command = "systemctl show " + serviceName + " --property=ExecMainPID --value";
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) {
            return "Unable to retrieve service information";
        }

        char buffer[128];
        std::string pid;
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            pid = buffer;
            pid.erase(pid.find_last_not_of(" \n\r") + 1); // Trim whitespace
        }
        pclose(pipe);

        if (pid.empty() || pid == "0") {
            return "Service process not running";
        }

        struct stat statBuf;
        std::string procPath = "/proc/" + pid + "/stat";
        if (stat(procPath.c_str(), &statBuf) == 0) {
            auto now = std::chrono::system_clock::now();
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()
            ).count() - statBuf.st_ctime;

            std::ostringstream oss;
            oss << uptime << " seconds";
            return oss.str();
        }

        return "Unable to retrieve uptime";
#endif
    }
    // Function to calculate usage metrics for a service and return them as JSON
    json::object calculateUsageMetrics(const std::string& serviceName) {
        json::object result;

        if (!isServiceRunning(serviceName)) {
            result["status"] = "Service is not running";
            return result;
        }

        // Simulate metrics collection (replace with actual logic or API calls)
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> requestDist(100, 1000);
        std::uniform_int_distribution<> threadDist(1, 50);
        std::uniform_int_distribution<> queueDist(0, 200);

        int requestCount = requestDist(gen);
        int activeThreads = threadDist(gen);
        int queueSize = queueDist(gen);

        // Populate the JSON result
        result["status"] = "Running";
        result["service_name"] = serviceName;
        json::object metrics;
        metrics["request_count"] = requestCount;
        metrics["active_threads"] = activeThreads;
        metrics["queue_size"] = queueSize;
        result["metrics"] = metrics;

        // Add uptime to the JSON result
        result["uptime"] = getServiceUptime(serviceName);

        return result;
    }

    __declspec(dllexport) const char* getServiceUsageMetrics(const char* serviceName)
    {
        json::object useageMetrics = calculateUsageMetrics(std::string(serviceName));
        global_string = json::serialize(useageMetrics);
        return global_string.c_str();
    }

    __declspec(dllexport) const char* getServicePerformanceMetrics(const char* serviceName)
    {
        ServiceMetrics metrics = getWindowsServiceMetrics(std::string(serviceName));
        boost::json::object jsonMetrics = to_json(metrics);
        global_string = boost::json::serialize(jsonMetrics).c_str();
        return global_string.c_str();
    }

    __declspec(dllexport) const char* getServiceReliabilityMetrics(const char* serviceName)
    {
        const char* ret = "WILL BE DONE WITH AFTER MVP - getAPIReliabilityMetrics";
        return ret;
    } 
    
   __declspec(dllexport) const char* getAPIReliabilityMetricsAndUsage(const char* serviceName)
    {
       std::vector<std::string> apis = {
            "http://10.0.10.173/api/Security/GetAllEquitiesForToday",
            // Add more API endpoints as needed
        };
 
        int num_requests = 50;  // Number of requests to send
        int failure_count = 0;
        for (auto& api_url : apis)
        {
            auto pos = api_url.find("//");
            auto end_pos = api_url.find('/', pos + 2);
            std::string host = api_url.substr(pos + 2, end_pos - pos - 2);
            std::string target = api_url.substr(end_pos);
            std::cout << host << "  " << target << std::endl;
 
            measure_api_performance(host, target, num_requests);
            return global_string.c_str();
        }

        const char* ret = "Something went wrong - getAPIReliabilityMetrics";
        return ret;
        
    }

    __declspec(dllexport) const char* getAPIPerformanceMetrics(const char* serviceName)
    {
        const char* ret = "WILL BE DONE WITH AFTER MVP - getServicePerformanceMetrics";
        return ret;
    }

 
    __declspec(dllexport) const char* startMonitoringService(const char* serviceName)
    {
        std::vector<std::string> serviceNames = { };
        serviceNames.push_back(serviceName);

        monitor_thread = true;
        double cpuThreshold = 5.0;  // in percentage
        size_t memoryThreshold = 2;  // in percentage
        int delaySeconds = 5;  // monitoring interval in seconds
          monitorServices(serviceNames, cpuThreshold, memoryThreshold, delaySeconds);


    // Wait for the thread to finish        
        return "SERVICE STARTED";
    }

    __declspec(dllexport) const char* stopMonitoringService(const char* serviceName)
    {
       monitor_thread = false;
       return "SERVICE STOPPED";
    }



    // Example usage
    int main() {

        std::string serviceName;
        std::cout << "Enter the service name: ";
        std::getline(std::cin, serviceName);
        std::cout << getServiceUsageMetrics(serviceName.c_str());

        //std::cout << getServicePerformanceMetrics(serviceName.c_str());

        //json::object useageMetrics = calculateUsageMetrics(serviceName);
        //std::cout << json::serialize(useageMetrics) << std::endl; // Serialize and print the JSON


       /* try {
            boost::asio::io_context io_context;
            unsigned short port = 8080;
            APIServer server(io_context, port);
            std::cout << "Server running on port " << port << std::endl;
            io_context.run();
        }
        catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }*/

        return 0;
    }

    //    // Expose a simple function
    //    __declspec(dllexport) const char* getServiceReliabilityMetrics(const char* serviceName)
    //    {
    //        const char* ret = "FUCK YOU BITCH! getServiceReliabilityMetrics";
    //        return ret;
    //    }
    //
    //    // Expose a simple function
    //    __declspec(dllexport) const char* getAPIUsageMetrics(const char* serviceName)
    //    {
    //        const char* ret = "FUCK YOU BITCH! getAPIUsageMetrics";
    //        return ret;
    //    }
    //
    //    // Expose a simple function
    //    __declspec(dllexport) const char* getAPIPerformanceMetrics(const char* serviceName)
    //    {
    //        const char* ret = "FUCK YOU BITCH! getAPIPerformanceMetrics";
    //        return ret;
    //    }
    //
    //    // Expose a simple function
    //    __declspec(dllexport) const char* getAPIReliabilityMetrics(const char* serviceName)
    //    {
    //        const char* ret = "FUCK YOU BITCH! getAPIReliabilityMetrics";
    //        return ret;
    //    }
    //}


}