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

void secret_solver(const char *ip_string, size_t secret_port, uint8_t groupnum);

int main(int argc, char *argv[]) {

    // Check for correct number of arguments
    if (argc != 6) {
        cerr << "Usage: ./puzzlesolver <IP address> <port1> <port2> <port3> <port4>" << endl;
        exit(1);
    }
    
    // Parse arguments
    const char *ip_string = argv[1];
    int port1 = atoi(argv[2]);
    int port2 = atoi(argv[3]);
    int port3 = atoi(argv[4]);
    int port4 = atoi(argv[5]);

    // size_t reponse_1 = get_response(ip_string, port1);
    // size_t reponse_2 = get_response(ip_string, port2);
    // size_t reponse_3 = get_response(ip_string, port3);
    // size_t reponse_4 = get_response(ip_string, port4);
    size_t evil_port        = 0;
    size_t expstn_port      = 0;
    size_t secret_port      = 4041;
    size_t signature_port   = 0;

    uint8_t groupnum = 51;
    uint64_t group_secret = 0xed9e8ddc;

    secret_solver(ip_string, secret_port, groupnum);

}

void secret_solver(const char *ip_string, size_t secret_port, uint8_t groupnum) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return;
    }

    // Set socket timeout using setsockopt
    struct timeval timeout;
    timeout.tv_sec = 2;  // 1-second timeout
    timeout.tv_usec = 0; // Clear the microseconds part
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Error setting socket timeout" << endl;
        close(sock);
        return;
    }

    // Server address setup
    struct sockaddr_in server_address;                                  // Initialize server address structure
    memset(&server_address, 0, sizeof(server_address));                 // Clear the structure
    server_address.sin_family = AF_INET;                                // Set address family to AF_INET
    server_address.sin_port = htons(secret_port);                       // Set port; use htons to convert to network byte order
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) { // Convert IP address string to binary
        cerr << "Invalid IP address" << endl;
        close(sock);
        return;
    }

    // Send a test datagram
    
    uint8_t message = groupnum;
    ssize_t sent_bytes = sendto(sock, &message, sizeof(message), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        // Handle sendto error
        cerr << "Error sending message" << endl;
        close(sock);
        return;
    }

    // Try to receive a response
    uint64_t challenge;
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, &challenge, BUFFER_SIZE, 0,
                                  (struct sockaddr *)&server_address, &addr_len);

    close(sock);  // Close the socket after use

    if (recv_bytes > 0) {
        // Convert the received challenge to host byte order
        challenge = ntohl(challenge);
        cout << "The group challenge is: " << hex << challenge << endl;
    }
}
