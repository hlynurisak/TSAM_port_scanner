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
#include <vector>    
#include <cerrno>
#include <sys/time.h>
#include <fcntl.h>
#include <list>

#define BUFFER_SIZE 1024
#define SECRET_PORT 1
#define EVIL_PORT 2
#define CHECKSUM_PORT 3
#define EXPSTN_PORT 4

using namespace std;

// Struct to hold the response from a port for easier handling
struct port_response {
    int port;
    bool is_open;
    char *response;
};

int  port_matcher(const char *ip_string, size_t port);
bool secret_solver(const char *ip_string, size_t secret_port, uint8_t groupnum, uint32_t group_secret);
bool evil_solver(const char *ip_string, size_t port, uint32_t signature);
bool checksum_solver(const char *ip_string, size_t port, uint32_t signature);
void second_checksum_solver(const char *ip_string, size_t port, uint8_t *last_six_bytes);
bool knock_solver(const char *ip_string, uint16_t port, uint32_t signature);
bool perform_port_knocking(const char *ip_string, const vector<uint16_t> &knock_sequence, uint32_t signature, const string &secret_phrase);
port_response get_port_response(const char *ip_string, int port);
uint16_t checksum(uint16_t *buf, int len);

string secret_phrase;
size_t secret_secret_port;
size_t secret_evil_port;


// Checksum calculator
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
    
    // Parse ip address
    const char *ip_string = argv[1];
    size_t secret_port   = 0;
    size_t evil_port     = 0;
    size_t checksum_port = 0;
    size_t expstn_port   = 0;

    // Loop through all ports to check if they are open and responding
    // while mapping them to variables
    int found_ports = 0;
    int tries = 0;

    while (found_ports < 4 && tries < 3) {
        for (int this_port = 2; this_port < 5; this_port++) {
            cout << "Checking port " << argv[this_port] << endl;
            size_t curr_port = port_matcher(ip_string, atoi(argv[this_port]));
            if (curr_port == SECRET_PORT) {
                secret_port = atoi(argv[this_port]);
                found_ports++;
            } else if (curr_port == EVIL_PORT) {
                evil_port = atoi(argv[this_port]);
                found_ports++;
            } else if (curr_port == CHECKSUM_PORT) {
                checksum_port = atoi(argv[this_port]);
                found_ports++;
            } else if (curr_port == EXPSTN_PORT) {
                expstn_port = atoi(argv[this_port]);
                found_ports++;
            }
        };
    };

    if (tries == 10) {
        cerr << "Failed to find all ports" << endl;
        return 1;
    };
    cout << "Found all ports" << endl;

    // TODO REMOVE BEFORE HANDIN
    evil_port        = 4048;
    expstn_port      = 4066;
    secret_port      = 4059;
    checksum_port    = 4047;

    size_t secret_secret_port = 4025;

    uint8_t groupnum = 51;
    uint32_t group_secret = 0xed9e8ddc;
    uint32_t group_challenge = 0xb99ec33e;
    uint32_t group_signature = 0xe24e0054;

    while (!secret_solver(ip_string, secret_port, groupnum, group_secret)) {
        secret_solver(ip_string, secret_port, groupnum, group_secret);
    }
    cout << "Secret port solved. Got: " << secret_secret_port << endl;
    
    while (!evil_solver(ip_string, evil_port, group_signature)) {
        evil_solver(ip_string, evil_port, group_signature);
    }
    cout << "Evil port solved. Got: " << secret_evil_port << endl;

    while (!checksum_solver(ip_string, checksum_port, group_signature)) {
        checksum_solver(ip_string, checksum_port, group_signature);
    }
    cout << "Checksum port solved. Got: " << secret_phrase << endl;


    if (!knock_solver(ip_string, expstn_port, group_signature)) {
        cerr << "Failed to get knock sequence from E.X.P.S.T.N." << endl;
        return 1;
    }

    cout << "Port knocking sequence completed successfully." << endl;

    return 0;
};

// A simple string matcher function to determine the port
int port_matcher(const char *ip_string, size_t port) {
    port_response response = get_port_response(ip_string, port);
    if (!response.is_open) {
        return 0;
    }
    if (response.response == nullptr) {
        return 0;
    }
    char first_chars[32];
    strncpy(first_chars, response.response, 32);
    first_chars[31] = '\0';
    if (strcmp(first_chars, "Greetings from S.E.C.R.E.T (Se") == 0) {
        return SECRET_PORT;
    } else if (strcmp(first_chars, "The dark side of network progra") == 0) {
        return EVIL_PORT;
    } else if (strcmp(first_chars, "Send me a 4-byte message contai") == 0) {
        return CHECKSUM_PORT;
    } else if (strcmp(first_chars, "Greetings! I am E.X.P.S.T.N, wh") == 0) {
        return EXPSTN_PORT;
    } else {
        return 0;
    }
    return 0;
}

// Taken from scanner.cpp
port_response get_port_response(const char *ip_string, int port) {
    port_response response;
    response.port = port;
    response.is_open = false;
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
        response.is_open = true;
        response.response = strdup(buffer);
        return response;
    } else {
        // If an error or nothing is received or the operation times out 
        // then assume port is closed
        return response;
    }
}


bool secret_solver(const char *ip_string, size_t port, uint8_t groupnum, uint32_t group_secret) {
    cout << "Solving the secret port..." << endl;
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return false;
    }

    // Set socket timeout using setsockopt
    struct timeval timeout;
    timeout.tv_sec = 1;  // 2-second timeout
    timeout.tv_usec = 0; // Clear the microseconds part
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

    // 1. Send group number to server
    uint8_t message = groupnum;
    ssize_t sent_bytes = sendto(sock, &message, sizeof(message), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        cerr << "Error sending message" << endl;
        close(sock);
        return false;
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
        return false;
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
        return false;
    }

    // 5. Receive port from server
    char buffer[BUFFER_SIZE];
    recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                          (struct sockaddr *)&server_address, &addr_len);
    if (recv_bytes > 0) {
        buffer[recv_bytes] = '\0';  // Null-terminate the received string
        cout << "Received: " << buffer << endl;

        // Find the port number in the response
        string response(buffer);
        size_t pos = response.find("port: ");
        if (pos != string::npos) {
            pos += 6;
            // Extract the port number and save to global variable
            secret_secret_port = stoi(response.substr(pos, pos + 4));
        } else {
            cerr << "Port not found in response" << endl;
        }
    } else {
        cerr << "Error receiving port" << endl;
        return false;
    }

    close(sock);  // Close the socket after use

    return true;
}

bool evil_solver(const char *ip_string, size_t port, uint32_t signature) {
    cout << "Solving the EVIL port ..." << endl;

    // Create a raw socket
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("Error creating raw socket");
        return false;
    }

    // Set IP_HDRINCL for MacOS
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
    ip_hdr->ip_src.s_addr = INADDR_ANY; // Autofill source IP
    ip_hdr->ip_dst.s_addr = inet_addr(ip_string);   // Destination IP (server)

    // Set up the UDP header
    struct udphdr *udp_hdr = (struct udphdr *) (datagram + sizeof(struct ip));
    udp_hdr->uh_sport = htons(54321);     // Source port
    udp_hdr->uh_dport = htons(port);      // Destination port (server port)
    udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + sizeof(signature)); // UDP length
    udp_hdr->uh_sum = 0;                  // Checksum initially 0 (calculated later)

    // Copy the signature into the data payload
    memcpy(datagram + sizeof(struct ip) + sizeof(struct udphdr), &signature, sizeof(signature));

    // Calculate the IP checksum (Not actually necessary)
    ip_hdr->ip_sum = checksum((unsigned short *)datagram, sizeof(struct ip));

    // Create pseudo-header for UDP checksum calculation
    struct pseudo_header {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t udp_length;
    };

    // Set up destination address for sending the packet
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(ip_string);

    // Send the packet using sendto()
    size_t packet_len = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(signature);
    if (sendto(raw_sock, datagram, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto failed");
        close(raw_sock);
        return false;
    }

    // Receive the response using a regular UDP socket
    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recv_sock < 0) {
        perror("Error creating recv socket");
        close(raw_sock);
        return false;
    }

    // Bind the receiving socket to the same port as the raw socket
    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(54321);  // Same source port
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
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
        cout << "Received: " << recv_buffer << endl;
        
        // Find the port number in the response
        string response(recv_buffer);
        size_t pos = response.find("port: ");
        if (pos != string::npos) {
            pos += 6;
            // Extract the port number and save to global variable
            secret_evil_port = stoi(response.substr(pos, pos + 4));
        } else {
            cerr << "Port not found in response" << endl;
        }
    } else {
        perror("recvfrom failed");
    }

    // Clean up
    close(recv_sock);
    close(raw_sock);

    return true;
}

bool checksum_solver(const char *ip_string, size_t port, uint32_t signature) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return false;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 1;
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

    // Send signature to the port
    ssize_t sent_bytes = sendto(sock, &signature, sizeof(signature), 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        cerr << "Error sending signature: " << strerror(errno) << endl;
        close(sock);
        return false;
    }

    cout << "Signature sent to " << ip_string << ":" << port << endl;

    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(struct sockaddr_in);
    ssize_t recv_bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                  (struct sockaddr *)&server_address, &addr_len);

    if (recv_bytes > 0) {
        buffer[recv_bytes] = '\0';  // Null-terminate response
        cout << "Received: " << buffer << endl;

        // Extract the last 6 bytes
        if (recv_bytes >= 6) {
            uint8_t last_six_bytes[6];
            memcpy(last_six_bytes, buffer + recv_bytes - 6, 6);

            // Extract the UDP checksum and source IP address
            uint16_t udp_checksum_network_order;
            uint32_t source_ip_network_order;

            memcpy(&udp_checksum_network_order, last_six_bytes, 2); // First 2 bytes (UDP checksum)
            memcpy(&source_ip_network_order, last_six_bytes + 2, 4); // Next 4 bytes (source IP)

            // Convert to host byte order
            uint16_t required_udp_checksum = ntohs(udp_checksum_network_order);
            uint32_t source_ip = ntohl(source_ip_network_order);

            // Print to check if its right
            printf("Extracted UDP checksum: 0x%04x\n", required_udp_checksum);
            struct in_addr ip_addr;
            ip_addr.s_addr = htonl(source_ip);
            printf("Extracted source IP: %s\n", inet_ntoa(ip_addr));

            // Construct packet to encapsualate and do checksum on
            size_t packet_size = sizeof(struct ip) + sizeof(struct udphdr);
            uint8_t *encapsulated_packet = new uint8_t[packet_size];

            // Fill in IPv4 header
            struct ip *inner_iph = (struct ip *)encapsulated_packet;
            inner_iph->ip_hl = 5;  // Header length (5 * 4 = 20 bytes)
            inner_iph->ip_v = 4;   // IPv4
            inner_iph->ip_tos = 0;
            inner_iph->ip_len = htons(packet_size);
            inner_iph->ip_id = htons(0);   // Identification
            inner_iph->ip_off = htons(0);  // No fragmentation
            inner_iph->ip_ttl = 64;        // Time to live
            inner_iph->ip_p = IPPROTO_UDP; // Protocol
            inner_iph->ip_sum = 0;         // Initial checksum
            inner_iph->ip_src.s_addr = source_ip_network_order; // Source IP (network byte order)
            inner_iph->ip_dst.s_addr = server_address.sin_addr.s_addr; // Destination IP

            // Fill in UDP header
            struct udphdr *inner_udph = (struct udphdr *)(encapsulated_packet + sizeof(struct ip));
            uint16_t source_port = 12345; // Random source port to start with
            inner_udph->uh_sport = htons(source_port);
            inner_udph->uh_dport = htons(port);
            inner_udph->uh_ulen = htons(sizeof(struct udphdr)); // UDP header length

            // Create a pseudo-header for the calculation
            struct pseudo_header {
                uint32_t src_addr;
                uint32_t dst_addr;
                uint8_t zero;
                uint8_t protocol;
                uint16_t udp_length;
            } psh;

            psh.src_addr = inner_iph->ip_src.s_addr;
            psh.dst_addr = inner_iph->ip_dst.s_addr;
            psh.zero = 0;
            psh.protocol = IPPROTO_UDP;
            psh.udp_length = inner_udph->uh_ulen;

            size_t pseudo_packet_len = sizeof(struct pseudo_header) + ntohs(psh.udp_length);
            uint8_t *pseudo_packet = new uint8_t[pseudo_packet_len];

            // Copy pseudo-header
            memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
            // Copy UDP header
            memcpy(pseudo_packet + sizeof(struct pseudo_header), inner_udph, ntohs(psh.udp_length));

            // Change the source port until the checksum comes back the same
            uint16_t current_checksum;
            if (current_checksum != ntohs(required_udp_checksum)) {
                bool checksum_matched = false;
                for (uint32_t sport = 0; sport <= 65535; sport++) {
                    // Try current port as source port
                    inner_udph->uh_sport = sport;

                    // Calculate checksum
                    memcpy(pseudo_packet + sizeof(struct pseudo_header), inner_udph, ntohs(psh.udp_length));
                    current_checksum = checksum((uint16_t *)pseudo_packet, pseudo_packet_len);

                    // Check if the checksum matches to the desired one
                    if (current_checksum == ntohs(required_udp_checksum)) {
                        checksum_matched = true;
                        break;
                    }
                }
                if (!checksum_matched) {
                    // Clear the memory if it can't get the correct checksum
                    cerr << "Could not find a source port to achieve the desired checksum." << endl;
                    delete[] encapsulated_packet;
                    delete[] pseudo_packet;
                    close(sock);
                    return false;
                }
                else {
                    // Set the checksum in the UDP header
                    inner_udph->uh_sum = current_checksum;
                }
            }

            // Send the packet with the checksum as the payload in another UDP message
            sent_bytes = sendto(sock, encapsulated_packet, packet_size, 0,
                                (struct sockaddr *)&server_address, sizeof(server_address));
            if (sent_bytes < 0) {
                cerr << "Error sending encapsulated packet: " << strerror(errno) << endl;
                delete[] encapsulated_packet;
                delete[] pseudo_packet;
                close(sock);
                return false;
            }

            cout << "Encapsulated packet sent to " << ip_string << ":" << port << endl;

            // Clean up
            delete[] encapsulated_packet;
            delete[] pseudo_packet;

            // Receive the response
            recv_bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                  (struct sockaddr *)&server_address, &addr_len);
            if (recv_bytes > 0) {
                buffer[recv_bytes] = '\0';  // Null-terminate the received string
                cout << "Received: " << buffer << endl;

                 // Find the secret phrase in the response
                string response(buffer);
                size_t pos = response.find("phrase: ");
                if (pos != string::npos) {
                    pos += 9;
                    // Extract the port number and save to global variable
                    secret_phrase = response.substr(pos, recv_bytes);
                    cout << "Secret phrase: " << secret_phrase << endl;
                }
            } else {
                cerr << "Error receiving response: " << strerror(errno) << endl;
                close(sock);
                return false;
            }

        } else {
            cerr << "Received message is too short to extract the last 6 bytes." << endl;
            close(sock);
            return false;
        }
    } else {
        cerr << "Error receiving response: " << strerror(errno) << endl;
        close(sock);
        return false;
    }

    close(sock);
    return true;
}

bool knock_solver(const char *ip_string, uint16_t port, uint32_t signature) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return false;
    }

    // Set socket timeout using setsockopt
    struct timeval timeout;
    timeout.tv_sec = 1;  // 2-second timeout
    timeout.tv_usec = 0; // Clear the microseconds part
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

    char secret_ports[10];
    cout << "Secret port: " << secret_secret_port << endl;
    cout << "Evil port: " << secret_evil_port << endl;
    snprintf(secret_ports, sizeof(secret_ports), "%zu,%zu", secret_secret_port, secret_evil_port);

    // Send the list of secret ports (comma-separated)
    cout << "Sending secret ports to E.X.P.S.T.N: " << secret_ports << "!" << endl;
    ssize_t sent_bytes = sendto(sock, &secret_ports, sizeof(secret_ports), 0, 
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        perror("Error sending secret ports to E.X.P.S.T.N.");
        close(sock);
        return false;
    }

    cout << "Sent " << sent_bytes << " bytes to E.X.P.S.T.N." << endl;

    // Wait for the response from E.X.P.S.T.N with the knock sequence
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&server_address, &addr_len);
    if (recv_bytes < 0) {
        perror("Error receiving knock sequence from E.X.P.S.T.N.");
        close(sock);
        return false;
    }

    buffer[recv_bytes] = '\0';  // Null-terminate the received string
    string response(buffer);
    cout << "Received from E.X.P.S.T.N: " << response << endl;

    // Parse the received knock sequence
    list<size_t> ports;
    bool done = false;
    int cur = 0;
    size_t curr_port = 0;
    while (!done) {
        if (isdigit(response[cur])) {
            curr_port = curr_port * 10 + atoi(&response[cur]);
            ports.push_back(curr_port);
            curr_port = 0;
            cur++;
        } else {
            ports.push_back(curr_port);
            done = true;
        }
        while (response[cur] != ',') {
            if (!isdigit(response[cur])) {
                done = true;
                break;
            }
            cur++;
        }
        cur++;
    }
    cout << "Parsed ports: ";
    for (int num : ports) {
        cout << num << " ";
    }
    cout << endl;
}

bool perform_port_knocking(const char *ip_string, size_t port, uint32_t group_signature, const string &secret_phrase) {
        // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return false;
    }

    // Set socket timeout using setsockopt
    struct timeval timeout;
    timeout.tv_sec = 1;  // 2-second timeout
    timeout.tv_usec = 0; // Clear the microseconds part
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

    // Send the knock sequence to the server
    
    // Signature to network byte order
    uint32_t signature_net_order = htonl(group_signature);
    // Prepare phrase
    size_t phrase_len = secret_phrase.length();

}

/*
// Receiving the list of ports to knock on from the oracle
    ssize_t recv_len = recvfrom(udp_sock.sock, recv_buffer, sizeof(recv_buffer) - 1, 0,
                                (struct sockaddr *) &udp_sock.recv_addr, &src_addr_len);
    if (recv_len < 0) {
        std::cerr << "[solve_EXPSTN] Error: recvfrom failed. (" << strerror(errno) << ")" << std::endl;
        return false;
    }

    // Ensuring the received data is null-terminated
    recv_buffer[recv_len] = '\0';

    // Logging the received response from the oracle
    std::cout << "[solve_EXPSTN] Received from Oracle Port " << oracle_port << ": " << recv_buffer << std::endl;

    // Parsing the received list of ports (assuming they are comma-separated)
    int sum = 0;
    int count = 0;
    int ports_to_knock[10] = {0}; // Adjust size as needed based on expected number of ports

    for (int i = 0; i < recv_len; ++i) {
        if (recv_buffer[i] != ',') {
            // Assuming ports can have multiple digits
            if (recv_buffer[i] >= '0' && recv_buffer[i] <= '9') {
                int num = recv_buffer[i] - '0';
                sum = sum * 10 + num;
            } else {
                std::cerr << "[solve_EXPSTN] Warning: Invalid character in port list: " << recv_buffer[i] << std::endl;
            }
        } else {
            if (count < 10) { // Prevent array overflow
                ports_to_knock[count++] = sum;
                sum = 0;
            } else {
                std::cerr << "[solve_EXPSTN] Warning: Too many ports received. Consider increasing ports_to_knock size." << std::endl;
                break;
            }
        }
    }
    if (count < 10) { // Add the last port if there is no trailing comma
        ports_to_knock[count++] = sum;
    }

    // Logging the list of ports to knock on
    std::cout << "\t\tPorts to Knock On: ";
    for (int i = 0; i < count; ++i) {
        std::cout << ports_to_knock[i];
        if (i < count - 1) std::cout << ", ";
    }
    std::cout << std::endl << std::endl;

    // Knocking on each port by sending the secret_phrase with signature and logging the response
    std::cout << "\t\tKnocking on ports..." << std::endl << std::endl;
    for (int port_index = 0; port_index < count; ++port_index) {
        uint16_t current_port = ports_to_knock[port_index];
        udp_sock.set_port(current_port);

        // Setting the message to always be secret_phrase
        const char* message = secret_phrase;
        size_t message_len = strlen(message);

        // Prepending the signature to the message
        // Convert the signature to network byte order
        uint32_t net_signature = htonl(secret_signature);
        // Creating a buffer to hold signature + message
        // Ensuring that the buffer is large enough
        size_t buffer_size = 4 + message_len;
        char* send_buffer_message = new char[buffer_size];
        memcpy(send_buffer_message, &net_signature, sizeof(net_signature));
        memcpy(send_buffer_message + 4, message, message_len);

        // Sending the secret_phrase with signature to the current port
        ssize_t knock_sent_len = sendto(udp_sock.sock, send_buffer_message, buffer_size, 0,
                                        (struct sockaddr *) &udp_sock.dest_addr, sizeof(udp_sock.dest_addr));
        delete[] send_buffer_message; // Freeing the allocated buffer

        if (knock_sent_len < 0) {
            std::cerr << "[solve_EXPSTN] Error: sendto failed on port " << current_port << ". (" << strerror(errno) << ")" << std::endl;
            continue; // Proceeding to the next port
        }
        std::cout << "[solve_EXPSTN] Sent to Port " << current_port << std::endl;

        // Receiving the response from the current port
        memset(recv_buffer, 0, sizeof(recv_buffer));
        ssize_t knock_recv_len = recvfrom(udp_sock.sock, recv_buffer, sizeof(recv_buffer) - 1, 0,
                                            (struct sockaddr *) &udp_sock.recv_addr, &src_addr_len);
        if (knock_recv_len < 0) {
            std::cerr << "[solve_EXPSTN] Error: recvfrom failed on port " << current_port << ". (" << strerror(errno) << ")" << std::endl;
            continue; // Proceeding to the next port
        }

        // Ensuring the received data is null-terminated
        recv_buffer[knock_recv_len] = '\0';

        // Logging the response from the current port
        std::cout << "[solve_EXPSTN] Received from Port " << current_port << ": " << recv_buffer << std::endl;
    }

    // Separator for clarity in console output
    std::cout << "----------------------------------------" << std::endl;
    return true;
*/