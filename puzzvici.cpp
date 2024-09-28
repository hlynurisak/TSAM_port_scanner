#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <iomanip>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include <sys/time.h>

#define BUFFER_SIZE 1024

using namespace std;

void secret_solver(const char *ip_string, uint8_t groupnum, uint32_t group_secret);
bool evil_solver(const char *ip_string, uint32_t signature);
void checksum_solver(const char *ip_string, uint32_t signature);
void second_checksum_solver(const char *ip_string, uint8_t *last_six_bytes);

uint16_t checksum(uint16_t *buf, int len);

// Function to calculate checksum
uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    uint16_t *w = buf;
    int nleft = len;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        uint16_t last_byte = 0;
        *(uint8_t *)(&last_byte) = *(uint8_t *)w;
        sum += last_byte;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return (uint16_t)(~sum);

}

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

    // secret_solver(ip_string, secret_port, groupnum, group_secret);
    evil_solver(ip_string, group_signature);
    // checksum_solver(ip_string, signature_port, group_signature);

    return 0;

}

void hex_print(const char data[], size_t length) {
    for (size_t i = 0; i < length; ++i) {
        cout << hex << setw(2) << setfill('0') << (static_cast<unsigned int>(data[i]) & 0xFF) << " ";
    }
}

void secret_solver(const char *ip_string, uint8_t groupnum, uint32_t group_secret) {
    
    size_t secret_port = 4059;  // Hardcode the secret port

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
    

    // Server address setup
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(secret_port);
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


bool evil_solver(const char *ip_string, uint32_t signature) {
    // Hardcode the destination port bc I can not reach the port from home network
    const uint16_t hardcoded_port = 4048;
    std::cout << "Solving the EVIL bit..." << std::endl;

    // Create a raw socket
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("Error creating raw socket");
        return false;
    }

    // Set IP_HDRINCL to indicate that we're including the IP header
    int optval = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("setsockopt(IP_HDRINCL) failed");
        close(raw_sock);
        return false;
    }

    // Prepare to send the packet
    char datagram[BUFFER_SIZE]; // Buffer for the packet
    memset(datagram, 0, BUFFER_SIZE);

    // Set up the IP header
    struct ip *ip_hdr = (struct ip *) datagram;
    ip_hdr->ip_hl = 5;               // Header length (5 * 4 = 20 bytes)
    ip_hdr->ip_v = 4;                // IPv4
    ip_hdr->ip_tos = 0;              // Type of service
    ip_hdr->ip_len = (sizeof(struct ip) + sizeof(struct udphdr) + sizeof(signature)); // Total length
    ip_hdr->ip_id = htons(54321);     // Random identifier
    ip_hdr->ip_off = (0x8000);   // Evil bit set (0x8000 means "Don't Fragment" + Evil Bit)
    ip_hdr->ip_ttl = 64;             // Time to live
    ip_hdr->ip_p = IPPROTO_UDP;      // Protocol (UDP)
    ip_hdr->ip_src.s_addr = inet_addr("127.0.0.1"); // Localhost as source IP
    ip_hdr->ip_dst.s_addr = inet_addr("127.0.0.1");   // Destination IP (server)

    // Set up the UDP header
    struct udphdr *udp_hdr = (struct udphdr *) (datagram + sizeof(struct ip));
    udp_hdr->uh_sport = htons(54321);     // Source port
    udp_hdr->uh_dport = htons(hardcoded_port);      // Destination port (server port)
    udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + sizeof(signature)); // UDP length
    udp_hdr->uh_sum = 0;                  // Checksum initially 0 (calculated later)

    // Copy the signature into the data payload
    uint32_t net_signature = htonl(signature);  // Convert signature to network byte order
    memcpy(datagram + sizeof(struct ip) + sizeof(struct udphdr), &net_signature, sizeof(net_signature));

    // Calculate the IP checksum
    ip_hdr->ip_sum = checksum((unsigned short *)datagram, sizeof(struct ip));

    // Create pseudo-header for UDP checksum calculation
    struct pseudo_header {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t udp_length;
    };

    struct pseudo_header psh;
    psh.src_ip = ip_hdr->ip_src.s_addr;
    psh.dst_ip = ip_hdr->ip_dst.s_addr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = udp_hdr->uh_ulen;

    // Create buffer for pseudo-header and UDP packet for checksum calculation
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(signature);
    char *pseudogram = new char[psize];

    // Copy pseudo-header and UDP header + data into pseudogram
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udp_hdr, sizeof(struct udphdr) + sizeof(signature));

    // Calculate the UDP checksum and set it in the UDP header
    udp_hdr->uh_sum = checksum((unsigned short *)pseudogram, psize);
    delete[] pseudogram; // Free the memory

    // Set up destination address for sending the packet
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(hardcoded_port);
    dest_addr.sin_addr.s_addr = inet_addr(ip_string);

    // Send the packet using sendto()
    size_t packet_len = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(signature);
    if (sendto(raw_sock, datagram, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto failed");
        close(raw_sock);
        return false;
    }
       
    std::cout << "Packet sent successfully to port " << hardcoded_port << "!" << std::endl;


    // Receive the response using a regular UDP socket
    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recv_sock < 0) {
        perror("Error creating recv socket");
        close(raw_sock);
        return false;
    }

    // Bind the receiving socket to the same port
    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(54321);  // Same source port
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("bind failed");
        close(recv_sock);
        close(raw_sock);
        return false;
    }

    // Set timeout for receiving
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        close(recv_sock);
        close(raw_sock);
        return false;
    }

    // Wait for the server's response
    char recv_buffer[BUFFER_SIZE];
    socklen_t recv_len = sizeof(recv_addr);
    ssize_t recv_bytes = recvfrom(recv_sock, recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&recv_addr, &recv_len);
    if (recv_bytes > 0) {
        recv_buffer[recv_bytes] = '\0';
        std::cout << "Received: " << recv_buffer << std::endl;
    } else {
        perror("recvfrom failed");
    }

    // Clean up
    close(recv_sock);
    close(raw_sock);

    return true;
}



void checksum_solver(const char *ip_string, uint32_t signature) {
    
    size_t checksum_port = 4047;  // Hardcoded checksum port

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
    server_address.sin_port = htons(checksum_port);
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

    cout << "Signature sent to " << ip_string << ":" << checksum_port << endl;

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

            // Call second_checksum_solver with the extracted bytes
            second_checksum_solver(ip_string, last_six_bytes);
        } else {
            cerr << "Received message is too short to extract last 6 bytes." << endl;
        }
    } else {
        cerr << "Error receiving response: " << strerror(errno) << endl;
    }

    close(sock);
}

void second_checksum_solver(const char *ip_string, uint8_t *last_six_bytes) {
    size_t checksum_port = 4047;  // Hardcoded checksum port

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
        cerr << "Error creating socket in second_checksum_solver: " << strerror(errno) << endl;
        return;
    }

    // Set up the server address to send the message back to the server
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(struct sockaddr_in));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(checksum_port);  // Send to the same port
    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) <= 0) {
        cerr << "Invalid IP address in second_checksum_solver" << endl;
        close(sock);
        return;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5-second timeout
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Error setting socket timeout in second_checksum_solver" << endl;
        close(sock);
        return;
    }

    // Define a payload for the inner UDP packet
    const char *inner_udp_payload = "Group 51";
    size_t inner_udp_payload_len = strlen(inner_udp_payload);

    // Prepare the encapsulated IPv4 packet with payload
    size_t ipv4_packet_len = sizeof(struct ip) + sizeof(struct udphdr) + inner_udp_payload_len;
    uint8_t *ipv4_packet = new uint8_t[ipv4_packet_len];

    // Fill in the IPv4 header
    struct ip *inner_iph = (struct ip *)ipv4_packet;
    inner_iph->ip_hl = 5;  // Header length (5 * 4 = 20 bytes)
    inner_iph->ip_v = 4;   // IPv4
    inner_iph->ip_tos = 0;
    inner_iph->ip_len = htons(ipv4_packet_len);
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
    inner_udph->uh_dport = htons(checksum_port);       // Destination port (server's port)
    inner_udph->uh_ulen = htons(sizeof(struct udphdr) + inner_udp_payload_len); // UDP header + payload length
    inner_udph->uh_sum = 0;                   // Initialize checksum to zero

    // Copy the payload after the UDP header
    memcpy(ipv4_packet + sizeof(struct ip) + sizeof(struct udphdr), inner_udp_payload, inner_udp_payload_len);

    // Compute UDP checksum including payload
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

    size_t pseudo_packet_len = sizeof(struct pseudo_header) + ntohs(psh.udp_length);
    uint8_t *pseudo_packet = new uint8_t[pseudo_packet_len];

    // Copy pseudo-header
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    // Copy UDP header and payload
    memcpy(pseudo_packet + sizeof(struct pseudo_header), inner_udph, ntohs(psh.udp_length));

    // Calculate checksum over pseudo-header and UDP header + payload
    inner_udph->uh_sum = checksum((unsigned short *)pseudo_packet, pseudo_packet_len);

    // Adjust the source port to achieve the desired checksum if necessary
    uint16_t original_checksum = ntohs(inner_udph->uh_sum);

    if (original_checksum != desired_checksum) {
        cout << "Adjusting source port to achieve desired UDP checksum..." << endl;
        bool found = false;
        for (uint16_t sport = 1; sport <= 65535; sport++) {
            inner_udph->uh_sport = htons(sport);

            // Recompute the checksum
            // Copy updated UDP header and payload into pseudo-packet
            memcpy(pseudo_packet + sizeof(struct pseudo_header), inner_udph, ntohs(psh.udp_length));

            inner_udph->uh_sum = checksum((unsigned short *)pseudo_packet, pseudo_packet_len);

            if (ntohs(inner_udph->uh_sum) == desired_checksum) {
                cout << "Found matching source port: " << sport << endl;
                found = true;
                break;
            }
        }
        if (!found) {
            cerr << "Could not find a source port to achieve the desired checksum." << endl;
            delete[] ipv4_packet;
            delete[] pseudo_packet;
            close(sock);
            return;
        }
    } else {
        cout << "Original checksum matches the desired checksum." << endl;
    }

    // Send the UDP message with the encapsulated IPv4 packet as payload
    ssize_t sent_bytes = sendto(sock, ipv4_packet, ipv4_packet_len, 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));

    if (sent_bytes < 0) {
        cerr << "Error sending encapsulated packet: " << strerror(errno) << endl;
    } else {
        cout << "Encapsulated IPv4 packet sent to " << ip_string << ":" << checksum_port << endl;
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

    // Clean up
    delete[] ipv4_packet;
    delete[] pseudo_packet;
    close(sock);
}
