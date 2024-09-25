#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>     // For iphdr
#include <netinet/udp.h>    // For udphdr
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include <sys/time.h>

#define BUFFER_SIZE 1024

using namespace std;

void secret_solver(const char *ip_string, size_t secret_port, uint8_t groupnum, uint32_t group_secret);
void evil_solver(const char *ip_string, size_t port, uint32_t signature);
void signature_solver(const char *ip_string, size_t port, uint32_t signature);

unsigned short checksum(unsigned short *ptr, int nbytes);

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
    size_t evil_port        = 4048;
    size_t expstn_port      = 4066;
    size_t secret_port      = 4059;
    size_t signature_port   = 4047;

    size_t secret_secret_port = 4025;

    uint8_t groupnum = 51;
    uint32_t group_secret = 0xed9e8ddc;
    uint32_t group_challenge = 0xb99ec33e;
    uint32_t group_signature = 0xe24e0054;

    secret_solver(ip_string, secret_port, groupnum, group_secret);
    evil_solver(ip_string, evil_port, group_signature);
    signature_solver(ip_string, signature_port, group_signature);

    return 0;

}

void secret_solver(const char *ip_string, size_t port, uint8_t groupnum, uint32_t group_secret) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return;
    }

    // Set socket timeout using setsockopt
    struct timeval timeout;
    timeout.tv_sec = 1;  // 2-second timeout
    timeout.tv_usec = 0; // Clear the microseconds part
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Error setting socket timeout" << endl;
        close(sock);
        return;
    }

    // Server address setup
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) {
        cerr << "Invalid IP address" << endl;
        close(sock);
        return;
    }

    // 1. Send group number to server
    uint8_t message = groupnum;
    ssize_t sent_bytes = sendto(sock, &message, sizeof(message), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        cerr << "Error sending message" << endl;
        close(sock);
        return;
    }

    // 2. Receive challenge from server
    uint32_t group_challenge;
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, &group_challenge, sizeof(group_challenge), 0,
                                  (struct sockaddr *)&server_address, &addr_len);

    if (recv_bytes == sizeof(group_challenge)) {
        // Convert the received challenge to host byte order
        group_challenge = ntohl(group_challenge);
    } else {
        cerr << "Error receiving challenge" << endl;
        close(sock);
        return;
    }

    // 3. Sign challenge with XOR
    uint32_t group_signature = group_challenge ^ group_secret;
    group_signature = htonl(group_signature);  // Convert to network byte order

    // 4. Create and send response with group number and signed challenge
    uint8_t response[5];
    response[0] = groupnum;
    memcpy(&response[1], &group_signature, sizeof(group_signature));

    // Send response to server
    sent_bytes = sendto(sock, response, sizeof(response), 0,
                        (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        cerr << "Error sending message" << endl;
        close(sock);
        return;
    }

    // 5. Receive port from server
    char buffer[BUFFER_SIZE];
    recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                          (struct sockaddr *)&server_address, &addr_len);
    if (recv_bytes > 0) {
        buffer[recv_bytes] = '\0';  // Null-terminate the received string
        cout << "Received: " << buffer << endl;
    } else {
        cerr << "Error receiving port" << endl;
    }

    close(sock);  // Close the socket after use

    return;
}


void evil_solver(const char *ip_string, size_t port, uint32_t signature) {
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return;
    }

    // Server address setup
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) {
        cerr << "Invalid IP address" << endl;
        close(sock);
        return;
    }

    // Convert signature to network byte order
    uint32_t net_signature = htonl(signature);
    
    // Send signature to evil port
    ssize_t sent_bytes = sendto(sock, &net_signature, sizeof(net_signature), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        cerr << "Error sending packet: " << strerror(errno) << endl;
        close(sock);
        return;
    }

    // Receive response
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                  (struct sockaddr *)&server_address, &addr_len);
    if (recv_bytes > 0) {
        buffer[recv_bytes] = '\0';  // Null-terminate the received string
        cout << "Received: " << buffer << endl;
    } else {
        cerr << "No response from evil port" << endl;
    }

    close(sock);
}


// Function to calculate checksum
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;

    return answer;
}

void signature_solver(const char *ip_string, size_t port, uint32_t signature) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5-second timeout
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Error setting socket timeout" << endl;
        close(sock);
        return;
    }

    // Server address setup
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) {
        cerr << "Invalid IP address" << endl;
        close(sock);
        return;
    }

    // Send signature to the port
    ssize_t sent_bytes = sendto(sock, &signature, sizeof(signature), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        cerr << "Error sending signature: " << strerror(errno) << endl;
        close(sock);
        return;
    }

    cout << "Signature sent to " << ip_string << ":" << port << endl;

    // Receive response from server
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                  (struct sockaddr *)&server_address, &addr_len);
    if (recv_bytes > 0) {
        buffer[recv_bytes] = '\0';  // Null-terminate the received string
        cout << "Received: " << buffer << endl;
    } else {
        cerr << "Error receiving response: " << strerror(errno) << endl;
    }

    close(sock);
}
