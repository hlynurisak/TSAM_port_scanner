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

void secret_solver(const char *ip_string, size_t secret_port, uint8_t groupnum, uint64_t group_secret);

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
    size_t evil_port        = 4012;
    size_t expstn_port      = 4024;
    size_t secret_port      = 4041;
    size_t signature_port   = 4083;

    uint8_t groupnum = 51;
    uint64_t group_secret = 0xed9e8ddc;

    secret_solver(ip_string, secret_port, groupnum, group_secret);

}

void secret_solver(const char *ip_string, size_t secret_port, uint8_t groupnum, uint64_t group_secret) {
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
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(secret_port);                       // htons to convert to network byte order
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) { // Convert IP address string to binary
        cerr << "Invalid IP address" << endl;
        close(sock);
        return;
    }

    // 1. Send group number to server
    uint8_t message = groupnum;
    ssize_t sent_bytes = sendto(sock, &message, sizeof(message), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        // Handle sendto error
        cerr << "Error sending message" << endl;
        close(sock);
        return;
    }

    // 2. Recieve challenge from server
    uint64_t group_challenge;
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, &group_challenge, BUFFER_SIZE, 0,
                                  (struct sockaddr *)&server_address, &addr_len);


    if (recv_bytes > 0) {
        // Convert the received challenge to host byte order
        group_challenge = ntohl(group_challenge);
        cout << "The group challenge is: " << hex << group_challenge << endl;
    }
    else {
        // Handle recvfrom error
        cerr << "Error receiving message" << endl;
        close(sock);  // Close the socket after use
        return;
    }

    // 3. Sign challenge with XOR
    uint64_t group_response = group_challenge ^ group_secret;
    group_response = htonl(group_response);  // Convert to network byte order

    // 4. Create and send response with group number and signed challenge
    // Create empty 5 byte buffer
    uint8_t response[5];
    // Group number in first byte
    response[0] = groupnum;
    // Copy response (4 bytes) to buffer
    memcpy(&response[1], &group_response, sizeof(group_response));

    // Send response to server
    sent_bytes = sendto(sock, response, sizeof(response), 0,
                        (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        // Handle sendto error
        cerr << "Error sending message" << endl;
        close(sock);
        return;
    }

    // 5. Receive port from server
    char buffer[BUFFER_SIZE];
    recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                          (struct sockaddr *)&server_address, &addr_len);
    if (recv_bytes > 0) {
        cout << buffer << endl;
    }
    close(sock);  // Close the socket after use
    return;
}
