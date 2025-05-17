CC = g++
CFLAGS = -Wall -std=c++17 -O2 -Wno-unused-but-set-variable
LIBS = -lssl -lcrypto -lpthread

all: client server

client: client.cpp
	$(CC) $(CFLAGS) client.cpp -o client $(LIBS)

server: server.cpp
	$(CC) $(CFLAGS) server.cpp -o server $(LIBS)

clean:
	rm -f client server

