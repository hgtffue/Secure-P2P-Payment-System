#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <vector>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mutex>
#include <iomanip> 


#define BUFFER_SIZE 1024

using namespace std;
SSL* ssl;
SSL_CTX* ctx;
string current_username;
int listening_port;
void* receiveMessages(void* arg);
int sock;

// 初始化 OpenSSL
SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

// 建立連線
void connectToServer(const char *ip, int port) {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cerr << "Socket creation failed!" << endl;
        exit(1);
    }
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serverAddr.sin_addr);
    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Connection to server failed!" << endl;
        exit(1);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    cout << "Connected to server." << endl;
}

// 註冊
void registerUser() {
    string username;

    cout << "Enter username: ";
    cin >> username;

    string message = "REGISTER#" + username;
    SSL_write(ssl, message.c_str(), message.length());
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    cout << "Server:\n" << buffer << endl;
}

// 登入
void loginUser() {
    string port;
    cout << "Enter username to login: ";
    cin >> current_username;
    cout << "Enter port number for login: ";
    cin >> port;

    string message = current_username + "#" + port;
    SSL_write(ssl, message.c_str(), message.length());
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    string response(buffer);

    // 提取 Session Key
    SSL_SESSION* session = SSL_get_session(ssl);
    unsigned char session_key[256];
    size_t session_key_length = SSL_SESSION_get_master_key(session, session_key, sizeof(session_key));

    // 將 Session Key 轉換為十六進位格式
    ostringstream session_key_hex;
    for (size_t i = 0; i < session_key_length; ++i) {
        session_key_hex << hex << setw(2) << setfill('0') << (int)session_key[i];
    }

    // 替換第二行的 PUBLIC_KEY 為 Session Key
    istringstream response_stream(response);
    ostringstream modified_response;
    string line;
    int line_number = 0;

    while (getline(response_stream, line)) {
        ++line_number;
        if (line_number == 2) {
            modified_response << session_key_hex.str() << "\n"; // 替換第二行
        } else {
            modified_response << line << "\n";
        }
    }

    // 輸出修改後的回應
    cout << "Server:\n" << modified_response.str() << endl;

    // 開啟客戶端伺服器
    int client_port = stoi(port);
    int client_server_sock;
    client_server_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in clientAddr;
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = INADDR_ANY;
    clientAddr.sin_port = htons(client_port);

    bind(client_server_sock, (sockaddr*)&clientAddr, sizeof(clientAddr));
    listen(client_server_sock, 5);

    // 啟動接收執行緒
    pthread_t tid;
    pthread_create(&tid, NULL, receiveMessages, (void*)&client_server_sock);
}

// 接收訊息的函數
void* receiveMessages(void* arg) {
    int client_server_sock = *(int*)arg;
    SSL_CTX* server_ctx = InitServerCTX();
    LoadCertificates(server_ctx, (char *)"client.crt", (char *)"client.key");

    while (true) {
        sockaddr_in peerAddr;
        socklen_t addrLen = sizeof(peerAddr);
        int peerSock = accept(client_server_sock, (sockaddr*)&peerAddr, &addrLen);
        if (peerSock < 0) continue;

        SSL* peer_ssl = SSL_new(server_ctx);
        SSL_set_fd(peer_ssl, peerSock);

        if (SSL_accept(peer_ssl) <= 0) {
            cerr << "SSL accept failed!" << endl;
            ERR_print_errors_fp(stderr);
            SSL_free(peer_ssl);
            close(peerSock);
            continue;
        }

        char buffer[BUFFER_SIZE] = {0};
        int bytesReceived = SSL_read(peer_ssl, buffer, BUFFER_SIZE);
        if (bytesReceived <= 0) {
            cerr << "SSL read failed!" << endl;
            SSL_free(peer_ssl);
            close(peerSock);
            continue;
        }

        string message(buffer);
        cout << "Received transfer request: " << message << endl;

        // 直接使用現有的伺服器連線進行轉發
        {
//            lock_guard<mutex> lock(dataMutex); // 保護 SSL 寫操作
            if (SSL_write(ssl, message.c_str(), message.length()) <= 0) {
                cerr << "Failed to forward message to server!" << endl;
                ERR_print_errors_fp(stderr);
            }
        }

        SSL_free(peer_ssl);
        close(peerSock);
    }

    SSL_CTX_free(server_ctx);
    return nullptr;
}


// 查詢資訊
void requestInfo() {
    string message = "List";
    SSL_write(ssl, message.c_str(), message.length());
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);

    // 將接收到的回應轉換為可處理的字串
    string response(buffer);

    // 提取 Session Key
    SSL_SESSION* session = SSL_get_session(ssl);
    unsigned char session_key[256];
    size_t session_key_length = SSL_SESSION_get_master_key(session, session_key, sizeof(session_key));

    // 將 Session Key 轉換為十六進位格式
    ostringstream session_key_hex;
    for (size_t i = 0; i < session_key_length; ++i) {
        session_key_hex << hex << setw(2) << setfill('0') << (int)session_key[i];
    }

    // 替換第二行的 PUBLIC_KEY 為 Session Key
    istringstream response_stream(response);
    ostringstream modified_response;
    string line;
    int line_number = 0;

    while (getline(response_stream, line)) {
        ++line_number;
        if (line_number == 2) {
            modified_response << session_key_hex.str() << "\n"; // 替換第二行
        } else {
            modified_response << line << "\n";
        }
    }

    // 輸出修改後的回應
    cout << "Server:\n" << modified_response.str() << endl;
}


// 查詢用戶資訊，根據用戶名從 List 中獲取 IP 和 Port
bool findUserInList(const string& receiver, string& host_ip, int& host_port) {
    // 發送 List 請求
    string message = "List";
    SSL_write(ssl, message.c_str(), message.length());
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);

    // 解析伺服器回應
    vector<string> lines;
    char* token = strtok(buffer, "\n");
    while (token) {
        lines.push_back(string(token));
        token = strtok(NULL, "\n");
    }

    // 從回應中解析在線用戶列表
    if (lines.size() < 4) {
        cout << "Invalid response from server." << endl;
        return false;
    }

    int user_count = stoi(lines[2]); // 第三行是在線用戶數量

    // 從第 4 行開始，每行是 username#ip#port
    for (int i = 3; i < 3 + user_count; ++i) {
        vector<string> user_info;
        char* user_token = strtok(const_cast<char*>(lines[i].c_str()), "#");
        while (user_token) {
            user_info.push_back(string(user_token));
            user_token = strtok(NULL, "#");
        }
        if (user_info.size() == 3 && user_info[0] == receiver) {
            host_ip = user_info[1];
            host_port = stoi(user_info[2]);
            return true;
        }
    }
    cout << "User " << receiver << " not found in list." << endl;
    return false;
}


void transfer() {
    string amount, receiver;
    cout << "Enter amount to transfer: ";
    cin >> amount;
    cout << "Enter receiver username: ";
    cin >> receiver;

    // 獲取接收者的 IP 和 Port
    string host_ip;
    int host_port;
    if (!findUserInList(receiver, host_ip, host_port)) {
        cout << "Failed to get receiver information." << endl;
        return;
    }

    // 創建 Socket
    int peer_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_sock < 0) {
        cerr << "Socket creation failed!" << endl;
        return;
    }

    sockaddr_in peerAddr;
    peerAddr.sin_family = AF_INET;
    inet_pton(AF_INET, host_ip.c_str(), &peerAddr.sin_addr);
    peerAddr.sin_port = htons(host_port);

    // 連接到接收者
    if (connect(peer_sock, (sockaddr*)&peerAddr, sizeof(peerAddr)) < 0) {
        cerr << "Connection to peer failed!" << endl;
        close(peer_sock);
        return;
    }

    // 創建新的 SSL Context 並初始化
    SSL_CTX* peerCtx = InitCTX();
    SSL* peer_ssl = SSL_new(peerCtx);
    SSL_set_fd(peer_ssl, peer_sock);

    // SSL 連接
    if (SSL_connect(peer_ssl) <= 0) {
        cerr << "SSL connection to peer failed!" << endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(peerCtx);
        close(peer_sock);
        return;
    }

    // 構造轉帳訊息
    string message = current_username + "#" + amount + "#" + receiver;
    SSL_write(peer_ssl, message.c_str(), message.length());

    // 接收回應
    char buffer[BUFFER_SIZE] = {0};
    SSL_read(ssl, buffer, BUFFER_SIZE);

    cout << "Response from receiver: " << buffer << endl;

    // 清理資源
    SSL_free(peer_ssl);
    SSL_CTX_free(peerCtx);
    close(peer_sock);
}

// 離線通知
void logout() {
    string message = "Exit";
    SSL_write(ssl, message.c_str(), message.length());
    close(sock);
    cout << "Bye" << endl;
}

int main() {
    cout << "Initializing SSL..." << endl;
    ctx = InitCTX();

    char serverIP[20];
    int port;

    cout << "Enter server IP: ";
    cin >> serverIP;
    cout << "Enter server port: ";
    cin >> port;

    connectToServer(serverIP, port);

    int choice;
    while (true) {
        cout << "\n1. Register\n2. Login\n3. Request Info\n4. Transfer\n5. Logout\nEnter your choice: ";
        cin >> choice;

        switch (choice) {
            case 1:
                registerUser();
                break;
            case 2:
                loginUser();
                break;
            case 3:
                requestInfo();
                break;
            case 4:
                transfer();
                break;
            case 5:
                logout();
                SSL_CTX_free(ctx);  // 清理 SSL 上下文
                return 0;
            default:
                cout << "Invalid choice. Please try again." << endl;
        }
    }
}
