# 加密轉帳系統 

## 編譯說明
本專案已提供 `Makefile`，可使用以下指令進行編譯：

```bash
make
```

若需清理編譯過的執行檔，請先使用：

```bash
make clean
```

編譯成功後將生成 `client` 和 `server` 可執行檔。  
亦可使用 `g++` 直接編譯，請依照需求操作。

## 執行說明

### 1. 啟動伺服器與客戶端程式
先啟動伺服器端：

```bash
./server <IP地址> <埠號>
```

再啟動客戶端程式：

```bash
./client
```

依提示輸入欲連接的伺服器 IP 與 Port。  
連接成功後會顯示主選單，可選擇下列操作：
- 註冊
- 登入
- 查詢資訊
- 轉帳
- 登出

### 2. 註冊功能
選擇 `1` 進行註冊。  
輸入使用者名稱後，Client 將自動向 Server 發送註冊請求，帳戶預設餘額為 `10,000`。

### 3. 登入功能
選擇 `2` 進行登入。  
輸入使用者名稱與 Port 號後，Client 將向 Server 發送登入請求並啟動接收訊息的執行緒。  
登入後會顯示帳戶餘額、用於解密的 Public Key 與上線清單。

### 4. 查詢功能
選擇 `3` 可查詢最新帳戶資訊，包含：
- 餘額
- Public Key
- 上線使用者清單

### 5. 轉帳功能
選擇 `4` 進行轉帳操作。  
輸入金額與收款方使用者名稱後，Client 將查詢對方的 IP 與 Port 並發送交易請求。  
成功後，顯示 `Transfer OK!`；收款方將同步收到通知。

### 6. 登出功能
選擇 `5` 可登出，Client 將通知 Server 並斷開連線。

## 安全傳輸實作說明

本系統採用 **TLS** 協議及 **RSA 非對稱加密** 確保通訊過程中資料的保密性與完整性。

### 1. TLS 加密通訊
- 使用 OpenSSL 實作 TLS 協定，保護資料不被竊聽或竄改。
- Server 使用 `SSL_CTX` 初始化安全上下文並載入 `.crt` 和 `.key` 憑證。
- Client 同樣載入憑證以建立安全通道。
- 使用 RSA 公鑰/私鑰進行身份驗證與密鑰交換。

### 2. 安全傳輸流程
1. **握手階段**：
    - Server 傳送憑證供 Client 驗證。
    - 使用 RSA 進行密鑰交換。
    - 協商對稱加密與雜湊演算法。

2. **資料傳輸階段**：
    - 雙方使用協商完成的會話金鑰進行對稱加密。
    - 傳送資料使用 `SSL_write()`，接收資料使用 `SSL_read()`。
    - 加密資料附加 MAC 確保資料未遭竄改。

3. **安全性保障**：
    - 每次通訊皆透過 TLS 加密。
    - 過期的會話金鑰無法解密歷史資料。
    - 攻擊者即使攔截資料亦無法重複利用金鑰。

## 環境說明

- **開發環境**：Ubuntu 64-bit 虛擬機  
- **執行環境**：Ubuntu 22.04 / macOS Ventura  
- **編譯器**：GCC 12.3.0  
- **必要套件**：
  - OpenSSL (`libssl-dev`)
  - Pthread (`libpthread`)

## 參考資料

- [C/C++ Linux TCP Socket Server/Client 教學](https://shengyu7697.github.io/cpp-linux-tcp-socket/)
- [TCP Socket Programming 筆記](https://zake7749.github.io/2015/03/17/SocketProgramming/)
- [GFG TCP Server-Client 教學](https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/)
- [C++ Thread Pool 教學](https://ncona.com/2019/05/using-thread-pools-in-cpp/)
- [OpenSSL 官方文件](https://www.openssl.org/docs/)
