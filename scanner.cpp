#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include <sys/time.h>

#define BUFFER_SIZE 1024

using namespace std;

bool check_port(const char *ip_string, int port);

int main(int argc, char *argv[]) {

    // Check for correct number of arguments
    if (argc != 4) {
        cerr << "Usage: ./scanner <IP address> <low port> <high port>" << endl;
        exit(1);
    }
    
    // Parse arguments
    const char *ip_string = argv[1];
    int low_port = atoi(argv[2]);
    int high_port = atoi(argv[3]);

    // Verify port range
    if (low_port < 0 || high_port < 0 || low_port > high_port) {
        cerr << "Invalid port range" << endl;
        exit(1);
    }

    // Check ports in the provided range
    for (int port = low_port; port <= high_port; port++) {
        if (check_port(ip_string, port)) {
            cout << ip_string << " / " << port << " OPEN" << endl;
        }
    }

    return 0;
}

bool check_port(const char *ip_string, int port) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return false;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 1;  // 1-second timeout
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Error setting socket timeout" << endl;
        close(sock);
        return false;
    }

    // Server address setup
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) {
        cerr << "Invalid IP address" << endl;
        close(sock);
        return false;
    }

    // Send a test datagram
    const char *message = "Port scan test";
    ssize_t sent_bytes = sendto(sock, message, strlen(message), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        // Handle sendto error
        close(sock);
        return false;
    }

    // Try to receive a response
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                  (struct sockaddr *)&server_address, &addr_len);

    close(sock);  // Close the socket after use

    if (recv_bytes > 0) {
        // Received a response; port is open
        return true;
    } else if (recv_bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        // Timeout occurred; assume port is closed or filtered
        return false;
    } else {
        // Other errors
        return false;
    }
}
