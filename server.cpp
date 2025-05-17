#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>
#include <sstream>
#include <condition_variable>
#include <queue>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

// Server data structures
unordered_map<string, int> accountBalances;    // User account balances
unordered_map<string, string> clientAddresses; // User addresses
unordered_map<string, int> clientPorts;        // User ports
unordered_map<string, SSL*> clientSSLConnections; // SSL connections
mutex dataMutex;                               // Mutex for thread-safe access

// Worker thread pool
queue<int> clientQueue;           // Queue of client sockets
mutex queueMutex;
condition_variable queueCondition;
bool serverRunning = true;


// SSL Context
SSL_CTX* ssl_ctx;

// Helper function to initialize SSL context
SSL_CTX* InitServerCTX() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_server_method(); // Use TLS method
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Load server certificates
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        cerr << "Private key does not match the public certificate" << endl;
        exit(EXIT_FAILURE);
    }
}


// Helper function to send data to client
void sendData(SSL* ssl, const string& message) {
    string formattedMessage = message + "\r\n";
    SSL_write(ssl, formattedMessage.c_str(), formattedMessage.size());
}

// Function to handle each client request
void handleClient(SSL* ssl) {
    char buffer[1024];
    string currentUsername;

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = SSL_read(ssl, buffer, sizeof(buffer));

        if (bytesReceived <= 0) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            break;
        }

        string request(buffer);
        cout << "Received from client: " << request << endl;

        string response;
        {
            lock_guard<mutex> lock(dataMutex);
            response.clear();

            if (request.rfind("REGISTER#", 0) == 0) {
                string username = request.substr(9);
                if (accountBalances.find(username) == accountBalances.end()) {
                    accountBalances[username] = 10000;
                    response = "100 OK\r\n";
                } else {
                    response = "210 FAIL\r\n";
                }
                sendData(ssl, response);

            } else if (request.find('#') != string::npos && count(request.begin(), request.end(), '#') == 1) {
                stringstream ss(request);
                string username, portStr;
                getline(ss, username, '#');
                getline(ss, portStr);
                int port = stoi(portStr);

                if (accountBalances.find(username) != accountBalances.end()) {
                    clientAddresses[username] = "127.0.0.1";
                    clientPorts[username] = port;
                    clientSSLConnections[username] = ssl;
                    currentUsername = username;

                    ostringstream oss;
                    oss << accountBalances[username] << "\r\n";
                    oss << "SERVER_PUBLIC_KEY\r\n";
                    oss << clientAddresses.size() << "\r\n";
                    for (const auto& [user, ip] : clientAddresses) {
                        oss << user << "#" << ip << "#" << clientPorts[user] << "\r\n";
                    }
                    response = oss.str();
                } else {
                    response = "220 AUTH_FAIL\r\n";
                }

                sendData(ssl, response);

            } else if (request.find('#') != string::npos && count(request.begin(), request.end(), '#') == 2) {
                stringstream ss(request);
                string sender, amountStr, receiver;
                getline(ss, sender, '#');
                getline(ss, amountStr, '#');
                getline(ss, receiver);

                double amount = stod(amountStr);
                bool transactionSuccess = false;

                if (accountBalances.find(sender) != accountBalances.end() &&
                    accountBalances.find(receiver) != accountBalances.end()) {
                    if (accountBalances[sender] >= amount && amount > 0) {
                        accountBalances[sender] -= amount;
                        accountBalances[receiver] += amount;
                        transactionSuccess = true;
                        response = "transfer OK\r\n";
                        if (clientSSLConnections.find(sender) != clientSSLConnections.end()) {
		                // 發送結果給 A
		                SSL* sender_ssl = clientSSLConnections[sender];
		                sendData(sender_ssl, "Transfer Completed: $" + amountStr + " to " + receiver);
		            }
                    } else {
                        response = "transfer FAIL \r\n";
                    }
                } else {
                    response = "transfer FAIL\r\n";
                }

            } else if (request == "List") {
                if (currentUsername.empty()) {
                    response = "220 AUTH_FAIL\r\n";
                } else {
                    ostringstream oss;
                    oss << accountBalances[currentUsername] << "\r\n";
                    oss << "PUBLIC_KEY\r\n";
                    oss << clientAddresses.size() << "\r\n";
                    for (const auto& [user, ip] : clientAddresses) {
                        oss << user << "#" << ip << "#" << clientPorts[user] << "\r\n";
                    }
                    response = oss.str();
                }
                sendData(ssl, response);

            } else if (request == "Exit") {
                if (!currentUsername.empty()) {
                    // 清理用戶資料
                    clientAddresses.erase(currentUsername);
                    clientPorts.erase(currentUsername);
                    clientSSLConnections.erase(currentUsername);
                    response = "Bye\r\n";
                    sendData(ssl, response);
                    cout << "User " << currentUsername << " logged out" << endl;
                }
                break;
            }
        }
    }


    SSL_free(ssl);
}


// Worker thread function
void workerThread() {
    while (serverRunning) {
        int clientSocket;
        {
            unique_lock<mutex> lock(queueMutex);
            queueCondition.wait(lock, [] { return !clientQueue.empty() || !serverRunning; });
            if (!serverRunning) return;

            clientSocket = clientQueue.front();
            clientQueue.pop();
        }

        SSL* ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, clientSocket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(clientSocket);
            continue;
        }

        handleClient(ssl);
    }
}

// Main server function
void startServer(const string& ip, int port) {
    ssl_ctx = InitServerCTX();
    LoadCertificates(ssl_ctx, "server.crt", "server.key");

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        cerr << "Error: Unable to create socket" << endl;
        return;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Error: Unable to bind to " << ip << ":" << port << endl;
        close(serverSocket);
        return;
    }

    listen(serverSocket, SOMAXCONN);

    vector<thread> workers;
    for (int i = 0; i < 4; ++i) {
        workers.emplace_back(workerThread);
    }

    cout << "Server listening on " << ip << ":" << port << endl;

    while (serverRunning) {
        sockaddr_in clientAddr{};
        socklen_t clientSize = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientSize);

        if (clientSocket < 0) {
            cerr << "Error: Failed to accept client connection" << endl;
            continue;
        }

        cout << "New client connected from "
             << inet_ntoa(clientAddr.sin_addr) << ":"
             << ntohs(clientAddr.sin_port) << endl;

        {
            lock_guard<mutex> lock(queueMutex);
            clientQueue.push(clientSocket);
        }
        queueCondition.notify_one();
    }

    close(serverSocket);

    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }

    SSL_CTX_free(ssl_ctx);
} 




int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <IP> <port>" << endl;
        return 1;
    }

    string ip = argv[1];
    int port = stoi(argv[2]);

    startServer(ip, port);

    return 0;
}

