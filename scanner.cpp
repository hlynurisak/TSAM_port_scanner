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

// Struct to hold the response from a port for easier handling
struct port_response {
    int port;
    bool open;
    char *response;
};

port_response get_port_response(const char *ip_string, int port);


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
        port_response response = get_port_response(ip_string, port);
        if (response.open) {
            cout << ip_string << ":" << port << " OPEN" << endl;
            if (response.response != nullptr) {
                cout << response.response << endl;
            }
        }
    }

    return 0;
}

port_response get_port_response(const char *ip_string, int port) {
    port_response response;
    response.port = port;
    response.open = false;
    response.response = nullptr;

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return response;
    }

    // Set socket timeout using setsockopt
    struct timeval timeout;
    timeout.tv_sec = 1;  // 1-second timeout
    timeout.tv_usec = 0; // Clear the microseconds part
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Error setting socket timeout" << endl;
        close(sock);
        return response;
    }

    // Server address setup
    struct sockaddr_in server_address;                                  // Initialize server address structure
    memset(&server_address, 0, sizeof(server_address));                 // Clear the structure
    server_address.sin_family = AF_INET;                                // Set address family to AF_INET
    server_address.sin_port = htons(port);                              // Set port; use htons to convert to network byte order
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) { // Convert IP address string to binary
        cerr << "Invalid IP address" << endl;
        close(sock);
        return response;
    }

    // Send a test datagram
    const char *message = "TSAM is the best!";
    ssize_t sent_bytes = sendto(sock, message, strlen(message), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        // Handle sendto error
        close(sock);
        return response;
    }

    // Try to receive a response
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                  (struct sockaddr *)&server_address, &addr_len);

    close(sock);  // Close the socket after use

    if (recv_bytes > 0) {
        // If there's a response then the port is open
        if (recv_bytes < BUFFER_SIZE) {
            buffer[recv_bytes] = '\0';      // Null-terminate the received data
        } else {
            buffer[BUFFER_SIZE - 1] = '\0'; // Null-terminate the received data
        }
        response.open = true;
        response.response = strdup(buffer);
        return response;
    } else {
        // If an error or nothing is received or the operation times out 
        // then assume port is closed
        return response;
    }
}
