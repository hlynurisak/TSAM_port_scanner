#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
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
void secret_phrase_solver(const char *ip_string, size_t port, uint8_t *last_six_bytes);

uint16_t checksum(unsigned short *ptr, int nbytes);

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
uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    for (; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return (uint16_t)(~sum);
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
    timeout.tv_sec = 1;
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

    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(struct sockaddr_in);
    ssize_t recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                  (struct sockaddr *)&server_address, &addr_len);

    if (recv_bytes > 0) {
        buffer[recv_bytes] = '\0';  // Null-terminate the received string
        cout << "Received: " << buffer << endl;

        // Extract the last 6 bytes
        if (recv_bytes >= 6) {
            uint8_t last_six_bytes[6];
            memcpy(last_six_bytes, buffer + recv_bytes - 6, 6);

            // Call secret_phrase_solver with the extracted bytes
            secret_phrase_solver(ip_string, port, last_six_bytes);
        } else {
            cerr << "Received message is too short to extract last 6 bytes." << endl;
        }
    } else {
        cerr << "Error receiving response: " << strerror(errno) << endl;
    }

    close(sock);
}

void secret_phrase_solver(const char *ip_string, size_t port, uint8_t *last_six_bytes) {
    // Extract desired UDP checksum (first 2 bytes)
    uint16_t desired_checksum_net_order;
    memcpy(&desired_checksum_net_order, last_six_bytes, sizeof(uint16_t));
    uint16_t desired_checksum = ntohs(desired_checksum_net_order); // Convert to host byte order

    // Extract source IP address (next 4 bytes)
    uint32_t source_ip_net_order;
    memcpy(&source_ip_net_order, last_six_bytes + 2, sizeof(uint32_t));
    uint32_t source_ip = ntohl(source_ip_net_order); // Convert to host byte order

    // Convert source IP to string
    char source_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &source_ip_net_order, source_ip_str, INET_ADDRSTRLEN);

    cout << "Desired UDP checksum: 0x" << hex << desired_checksum << endl;
    cout << "Source IP address: " << source_ip_str << endl;

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);  // Standard UDP socket
    if (sock < 0) {
        cerr << "Error creating socket in secret_phrase_solver: " << strerror(errno) << endl;
        return;
    }

    // Set up the server address to send the message back to the server
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(struct sockaddr_in));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);  // Send to the same port
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) {
        cerr << "Invalid IP address in secret_phrase_solver" << endl;
        close(sock);
        return;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5-second timeout
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Error setting socket timeout in secret_phrase_solver" << endl;
        close(sock);
        return;
    }

    // Prepare the encapsulated IPv4 packet
    uint8_t ipv4_packet[sizeof(struct ip) + sizeof(struct udphdr)];

    // Fill in the IPv4 header
    struct ip *inner_iph = (struct ip *)ipv4_packet;
    inner_iph->ip_hl = 5;  // Header length (5 * 4 = 20 bytes)
    inner_iph->ip_v = 4;   // IPv4
    inner_iph->ip_tos = 0;
    inner_iph->ip_len = htons(sizeof(ipv4_packet));
    inner_iph->ip_id = htons(0);   // Identification
    inner_iph->ip_off = htons(0);  // No fragmentation
    inner_iph->ip_ttl = 64;        // Time to live
    inner_iph->ip_p = IPPROTO_UDP; // Protocol
    inner_iph->ip_sum = 0;         // Initial checksum
    inner_iph->ip_src.s_addr = source_ip_net_order;   // Source IP (network byte order)
    inner_iph->ip_dst.s_addr = inet_addr(ip_string);  // Destination IP (server's IP)

    
    // Fill in the UDP header
    struct udphdr *inner_udph = (struct udphdr *)(ipv4_packet + sizeof(struct ip));
    inner_udph->uh_sport = htons(12345);      // Source port (arbitrary)
    inner_udph->uh_dport = htons(port);       // Destination port (server's port)
    inner_udph->uh_ulen = htons(sizeof(struct udphdr)); // UDP header length
    inner_udph->uh_sum = 0;                   // Initialize checksum to zero

    // Compute UDP checksum
    // Prepare the pseudo-header
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    };

    struct pseudo_header psh;
    psh.src_addr = inner_iph->ip_src.s_addr;
    psh.dst_addr = inner_iph->ip_dst.s_addr;
    psh.zero = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = inner_udph->uh_ulen;

    // Calculate checksum over pseudo-header and UDP header
    uint8_t pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct udphdr)];
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), inner_udph, sizeof(struct udphdr));

    inner_udph->uh_sum = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

    // Adjust the source port to achieve the desired checksum if necessary
    uint16_t original_checksum = ntohs(inner_udph->uh_sum);

    if (original_checksum != desired_checksum) {
        cout << "Adjusting source port to achieve desired UDP checksum..." << endl;
        bool found = false;
        for (uint16_t sport = 1; sport <= 65535; sport++) {
            inner_udph->uh_sport = htons(sport);

            // Recompute the checksum
            memcpy(pseudo_packet + sizeof(struct pseudo_header), inner_udph, sizeof(struct udphdr));
            inner_udph->uh_sum = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

            if (ntohs(inner_udph->uh_sum) == desired_checksum) {
                cout << "Found matching source port: " << sport << endl;
                found = true;
                break;
            }
        }
        if (!found) {
            cerr << "Could not find a source port to achieve the desired checksum." << endl;
            close(sock);
            return;
        }
    } else {
        cout << "Original checksum matches the desired checksum." << endl;
    }

    // Send the UDP message with the encapsulated IPv4 packet as payload
    ssize_t sent_bytes = sendto(sock, ipv4_packet, sizeof(ipv4_packet), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));

    if (sent_bytes < 0) {
        cerr << "Error sending encapsulated packet: " << strerror(errno) << endl;
    } else {
        cout << "Encapsulated IPv4 packet sent to " << ip_string << ":" << port << endl;
    }

    // Receive the secret message from the server
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(struct sockaddr_in);
    ssize_t recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0,
                                  (struct sockaddr *)&server_address, &addr_len);

    if (recv_bytes > 0) {
        buffer[recv_bytes] = '\0';  // Null-terminate the received string
        cout << "Secret Message Received: " << buffer << endl;
    } else {
        cerr << "Error receiving secret message: " << strerror(errno) << endl;
    }

    close(sock);
}
