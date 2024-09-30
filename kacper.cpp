#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


#define GROUP_NUMBER 150
#define GROUP_SECRET 0x483b2879
#define IP_EVIL_BIT 0x8000


// A class to simplify the usage of the UDP socket
class socket_handler {
public:
    int sock;
    sockaddr_in dest_addr;
    sockaddr_in recv_addr;
    struct timeval timeout;

    void set_socket(const std::string& ip) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }
        dest_addr.sin_family = AF_INET;
        inet_aton(ip.c_str(), &dest_addr.sin_addr);
    }

    void set_port(uint16_t port) {
        dest_addr.sin_port = htons(port);
    }

    void set_timeout(long timeout_ms, long timeout_s = 0) {
        timeout.tv_usec = timeout_ms * 1000; // Convert ms to us
        timeout.tv_sec = timeout_s;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    }
};

#pragma pack(push, 1) // Disable padding
struct ip_header {
    uint8_t  ip_hl_v;       // Version (4 bits) + Internet header length (4 bits)
    uint8_t  ip_tos;        // Type of service
    uint16_t ip_len;        // Total length
    uint16_t ip_id;         // Identification
    uint16_t ip_off;        // Fragment offset field
    uint8_t  ip_ttl;        // Time to live
    uint8_t  ip_p;          // Protocol
    uint16_t ip_sum;        // Checksum
    uint32_t ip_src;        // Source address
    uint32_t ip_dst;        // Destination address
};

struct udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};
#pragma pack(pop)

struct pseudo_header {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t seg_len;
};

// Creates a socket with the given IP address
socket_handler create_socket(const std::string& ip) {
    socket_handler udp_socket;
    udp_socket.set_socket(ip);
    udp_socket.set_timeout(0, 1); // Increased timeout to 5 seconds
    return udp_socket;
}

// Function to compute the checksum
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    
    return answer;
}

// Function to interact with the S.E.C.R.E.T port
bool solve_SECRET(socket_handler& udp_socket, uint16_t port, uint8_t group_number, uint32_t group_secret, char *secret_port, uint32_t& secret_signature) {
    std::cout << "----------------------------------------" << std::endl << std::endl;
    std::cout << "\t\tSolving SECRET Port " << port << "..." << std::endl << std::endl;

    // Setting the port number for the socket
    udp_socket.set_port(port);

    // Sending the group number as a single byte
    ssize_t sent_len = sendto(udp_socket.sock, &group_number, sizeof(group_number), 0,
                              (struct sockaddr*)&udp_socket.dest_addr, sizeof(udp_socket.dest_addr));
    if (sent_len < 0) {
        std::cerr << "[solve_SECRET] Error: Failed to send group number. (" << strerror(errno) << ")" << std::endl;
        return false;
    }
    std::cout << "[solve_SECRET] Sent group number " << static_cast<int>(group_number) << " to Port " << port << std::endl;

    // Receiving the 4-byte challenge from the server
    uint32_t challenge;
    socklen_t addr_len = sizeof(udp_socket.recv_addr);
    ssize_t recv_len = recvfrom(udp_socket.sock, &challenge, sizeof(challenge), 0,
                                (struct sockaddr*)&udp_socket.recv_addr, &addr_len);
    if (recv_len < 0) {
        std::cerr << "[solve_SECRET] Error: Failed to receive challenge. (" << strerror(errno) << ")" << std::endl;
        return false;
    } else if (recv_len != sizeof(challenge)) {
        std::cerr << "[solve_SECRET] Error: Received incorrect challenge size (" << recv_len << " bytes)." << std::endl;
        return false;
    }
    std::cout << "[solve_SECRET] Received 4-byte challenge from Port " << port << std::endl;

    // Converting the challenge from network byte order to host byte order
    challenge = ntohl(challenge);

    // Signing the challenge by XOR-ing with the group's secret
    uint32_t signed_challenge = challenge ^ group_secret;
    std::cout << "[solve_SECRET] Computed signed challenge." << std::endl;

    // Preparing the 5-byte message: group_number followed by signed_challenge
    uint8_t message[5];
    message[0] = group_number;
    uint32_t net_signed_challenge = htonl(signed_challenge);
    memcpy(&message[1], &net_signed_challenge, sizeof(net_signed_challenge));

    // Sending the signed challenge back to the server
    sent_len = sendto(udp_socket.sock, message, sizeof(message), 0,
                      (struct sockaddr*)&udp_socket.dest_addr, sizeof(udp_socket.dest_addr));
    if (sent_len < 0) {
        std::cerr << "[solve_SECRET] Error: Failed to send signed challenge. (" << strerror(errno) << ")" << std::endl;
        return false;
    }
    std::cout << "[solve_SECRET] Sent signed challenge to Port " << port << std::endl;

    // Receiving the response message from the server
    char recv_buffer[1024];
    recv_len = recvfrom(udp_socket.sock, recv_buffer, sizeof(recv_buffer) - 1, 0,
                        (struct sockaddr*)&udp_socket.recv_addr, &addr_len);
    if (recv_len < 0) {
        std::cerr << "[solve_SECRET] Error: Failed to receive response message. (" << strerror(errno) << ")" << std::endl;
        return false;
    }

    // Ensuring the received data is null-terminated
    recv_buffer[recv_len] = '\0';

    // Logging the received message
    std::cout << "[solve_SECRET] Received from Port " << port << ": " << recv_buffer << std::endl;

    // Extracting the secret port number from the received message
    std::string response(recv_buffer);
    size_t colon_pos = response.rfind(':');
    size_t exclam_pos = response.rfind('!');

    if (colon_pos != std::string::npos && exclam_pos != std::string::npos && exclam_pos > colon_pos) {
        // Extracting the substring between the last colon and exclamation mark
        std::string port_str = response.substr(colon_pos + 1, exclam_pos - colon_pos - 1);

        // Trimming any leading and trailing whitespace
        port_str.erase(0, port_str.find_first_not_of(" \t"));
        port_str.erase(port_str.find_last_not_of(" \t") + 1);

        // Copying the port string to the secret_port parameter and ensuring null-termination
        strncpy(secret_port, port_str.c_str(), 4); // Assuming secret_port has at least 5 bytes (4 digits + null terminator)
        secret_port[4] = '\0'; // Ensure null-termination

        std::cout << "[solve_SECRET] Extracted secret port: " << secret_port << std::endl;
    } else {
        std::cerr << "[solve_SECRET] Error: Failed to extract secret port from the message." << std::endl;
        return false;
    }

    // Storing the signed challenge as the secret signature for future use
    secret_signature = signed_challenge;
    std::cout << "[solve_SECRET] Stored secret signature for future interactions." << std::endl;

    std::cout << std::endl << "----------------------------------------" << std::endl << std::endl;
    return true;
}

// Function to interact with the simple port
bool solve_simple_port(socket_handler& udp_socket, uint16_t port, uint32_t secret_signature, char *secret_phrase) {
    // Separator for clarity in console output
    std::cout << "----------------------------------------" << std::endl << std::endl;
    std::cout << "\t\tSolving Simple Port " << port << "..." << std::endl << std::endl;

    // Setting the port number for the socket
    udp_socket.set_port(port);

    // Sending the 4-byte signature to the specified port
    uint32_t net_signature = htonl(secret_signature);
    ssize_t sent_len = sendto(udp_socket.sock, &net_signature, sizeof(net_signature), 0,
                              (struct sockaddr*)&udp_socket.dest_addr, sizeof(udp_socket.dest_addr));
    if (sent_len < 0) {
        std::cerr << "[solve_simple_port] Error: Failed to send signature. (" << strerror(errno) << ")" << std::endl;
        return false;
    }
    std::cout << "[solve_simple_port] Sent 4-byte signature to Port " << port << std::endl;

    // Receiving the message from the port
    char recv_buffer[2048];
    socklen_t addr_len = sizeof(udp_socket.recv_addr);
    ssize_t recv_len = recvfrom(udp_socket.sock, recv_buffer, sizeof(recv_buffer) - 1, 0,
                                (struct sockaddr*)&udp_socket.recv_addr, &addr_len);
    if (recv_len < 0) {
        std::cerr << "[solve_simple_port] Error: Failed to receive message. (" << strerror(errno) << ")" << std::endl;
        return false;
    }

    // Null-terminate the received data to ensure it's a valid C-string
    recv_buffer[recv_len] = '\0';

    // Log the full response from the port
    std::cout << "[solve_simple_port] Received from Port " << port << ": " << recv_buffer << std::endl;

    // Check if the message is long enough to extract the last 6 bytes
    size_t message_length = recv_len;
    if (message_length >= 6) {
        uint8_t last_six_bytes[6];
        memcpy(last_six_bytes, &recv_buffer[message_length - 6], 6);

        // Extract the UDP checksum and source IP address from the last 6 bytes
        uint16_t udp_checksum_network_order;
        uint32_t source_ip_network_order;

        memcpy(&udp_checksum_network_order, last_six_bytes, 2); // First 2 bytes for checksum
        memcpy(&source_ip_network_order, last_six_bytes + 2, 4); // Next 4 bytes for source IP

        // Convert from network byte order to host byte order
        uint16_t required_udp_checksum = ntohs(udp_checksum_network_order);
        uint32_t source_ip = ntohl(source_ip_network_order);

        // Print extracted values for verification using printf to match original code
        printf("[solve_simple_port] Extracted UDP checksum: 0x%04x\n", required_udp_checksum);
        struct in_addr ip_addr;
        ip_addr.s_addr = htonl(source_ip);
        printf("[solve_simple_port] Extracted source IP: %s\n", inet_ntoa(ip_addr));

        // Now construct the encapsulated packet

        // Inner IPv4 header
        struct ip_header iphdr;
        memset(&iphdr, 0, sizeof(iphdr));

        iphdr.ip_hl_v = (4 << 4) | 5; // Version and header length
        iphdr.ip_tos = 0;
        iphdr.ip_len = htons(sizeof(iphdr) + sizeof(udp_header)); // Total length
        iphdr.ip_id = htons(0);
        iphdr.ip_off = htons(0);
        iphdr.ip_ttl = 64;
        iphdr.ip_p = IPPROTO_UDP;
        iphdr.ip_sum = 0; // Checksum (can be zero in payload)
        iphdr.ip_src = htonl(source_ip); // Source IP address
        iphdr.ip_dst = udp_socket.dest_addr.sin_addr.s_addr; // Destination IP

        // Inner UDP header
        struct udp_header udphdr;
        memset(&udphdr, 0, sizeof(udphdr));

        uint16_t source_port = 1024; // Starting from 1024 to avoid hardcoded value
        udphdr.source = htons(source_port);
        udphdr.dest = htons(port);
        udphdr.len = htons(sizeof(udp_header)); // Length of UDP header (8 bytes) + payload (0 bytes)
        udphdr.check = 0; // Initially zero for checksum calculation

        // Prepare pseudo-header for checksum calculation
        struct pseudo_header {
            uint32_t src_addr;
            uint32_t dst_addr;
            uint8_t zero;
            uint8_t protocol;
            uint16_t udp_length;
        } __attribute__((packed)) pseudo_hdr;

        pseudo_hdr.src_addr = htonl(source_ip);
        pseudo_hdr.dst_addr = udp_socket.dest_addr.sin_addr.s_addr;
        pseudo_hdr.zero = 0;
        pseudo_hdr.protocol = IPPROTO_UDP;
        pseudo_hdr.udp_length = udphdr.len; // UDP length

        // Calculate checksum
        size_t psize = sizeof(pseudo_hdr) + sizeof(udphdr);
        char *pseudogram = new char[psize];

        bool checksum_matched = false;
        for (uint16_t sp = 1024; sp <= 65535; sp++) {
            source_port = sp;
            udphdr.source = htons(source_port);
            udphdr.check = 0; // Reset checksum

            // Prepare pseudogram for checksum calculation
            memcpy(pseudogram, &pseudo_hdr, sizeof(pseudo_hdr));
            memcpy(pseudogram + sizeof(pseudo_hdr), &udphdr, sizeof(udphdr));

            // Compute the checksum
            uint16_t computed_checksum = checksum((uint16_t*)pseudogram, psize);

            // Set udphdr.check to computed checksum
            udphdr.check = computed_checksum;

            if (ntohs(computed_checksum) == required_udp_checksum) {
                checksum_matched = true;
                break;
            }
        }

        if (!checksum_matched) {
            std::cerr << "[solve_simple_port] Error: Failed to find a matching checksum." << std::endl;
            delete[] pseudogram;
            return false;
        }

        // Encapsulate headers into a buffer
        size_t packet_size = sizeof(iphdr) + sizeof(udphdr); // IP header + UDP header
        char *packet = new char[packet_size];

        memcpy(packet, &iphdr, sizeof(iphdr));
        memcpy(packet + sizeof(iphdr), &udphdr, sizeof(udphdr));

        // Send the encapsulated packet as the payload to Port 4022
        sent_len = sendto(udp_socket.sock, packet, packet_size, 0,
                          (struct sockaddr*)&udp_socket.dest_addr, sizeof(udp_socket.dest_addr));
        if (sent_len < 0) {
            std::cerr << "[solve_simple_port] Error: Failed to send encapsulated packet. (" << strerror(errno) << ")" << std::endl;
            delete[] pseudogram;
            delete[] packet;
            return false;
        }
        std::cout << "[solve_simple_port] Sent encapsulated packet to Port " << port << std::endl;

        // Receive the response after sending the encapsulated packet
        recv_len = recvfrom(udp_socket.sock, recv_buffer, sizeof(recv_buffer) - 1, 0,
                            (struct sockaddr*)&udp_socket.recv_addr, &addr_len);
        if (recv_len < 0) {
            std::cerr << "[solve_simple_port] Error: Failed to receive response after sending encapsulated packet. (" << strerror(errno) << ")" << std::endl;
            delete[] pseudogram;
            delete[] packet;
            return false;
        }

        // Null-terminate and print the response
        recv_buffer[recv_len] = '\0';
        std::cout << "[solve_simple_port] Response from Port " << port << ": " << recv_buffer << std::endl;

        // Extract the secret phrase from the response
        // Assuming the secret phrase is enclosed in double quotes
        std::string response(recv_buffer);
        size_t first_quote = response.find('"');
        size_t last_quote = response.rfind('"');

        if (first_quote != std::string::npos && last_quote != std::string::npos && last_quote > first_quote) {
            std::string phrase = response.substr(first_quote + 1, last_quote - first_quote - 1);
            strncpy(secret_phrase, phrase.c_str(), 31);
            secret_phrase[31] = '\0'; // Ensure null-termination
            std::cout << "[solve_simple_port] Extracted secret phrase: " << secret_phrase << std::endl;
        } else {
            std::cerr << "[solve_simple_port] Error: Failed to extract secret phrase from the response." << std::endl;
            delete[] pseudogram;
            delete[] packet;
            return false;
        }

        // Clean up dynamically allocated memory
        delete[] pseudogram;
        delete[] packet;

        std::cout << std::endl << "----------------------------------------" << std::endl << std::endl;
        return true;
    }
}

// Function to interact with the evil port
bool solve_evil_port(socket_handler &udp_sock, uint16_t port, char *evil_port, uint32_t signature) {
    // Separator for clarity in console output
    std::cout << "----------------------------------------" << std::endl << std::endl;
    std::cout << "\t\tSolving the \033[91mEVIL\033[0m bit..." << std::endl << std::endl;

    // Setting the port number for the socket
    udp_sock.set_port(port); 

    char recv_buff[1024];
    socklen_t rcv_len = sizeof(udp_sock.recv_addr);

    // Preparing the datagram with enough space
    char datagram[64] = {0};
    char *data;
    char *pseudogram;

    // Setting up the IP header
    struct ip *iph = (struct ip *) datagram;

    // Setting up the UDP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof(struct ip));
    data = datagram + sizeof(struct ip) + sizeof(struct udphdr);
    struct pseudo_header psh;

    // Converting the signature to network byte order
    uint32_t net_signature = htonl(signature);

    // Inserting the 4-byte signature into the data section
    memcpy(data, &net_signature, sizeof(net_signature));

    // Creating a raw socket for sending the packet
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw < 0) {
        std::cerr << "[solve_evil_port] Error: Failed to create raw socket. (" << strerror(errno) << ")" << std::endl;
        return false;
    }

    // Preparing the sockaddr_in structure for the raw socket
    struct sockaddr_in raw_sin;
    raw_sin.sin_family = AF_INET;
    raw_sin.sin_port = htons(5100); // Arbitrary port

    // Retrieving the source address and port of the socket
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    if (getsockname(udp_sock.sock, (struct sockaddr *) &src_addr, &src_addr_len) < 0) {
        std::cerr << "[solve_evil_port] Error: getsockname failed. (" << strerror(errno) << ")" << std::endl;
        close(raw);
        return false;
    }

    // Configuring the IP header fields
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
    iph->ip_id = htonl(0x1234);
    iph->ip_off = htons(0b10000000); // Setting the evil bit
    iph->ip_ttl = 64;
    iph->ip_p = 17; // UDP protocol
    iph->ip_sum = 0; // Checksum initially zero
    iph->ip_src = src_addr.sin_addr;
    iph->ip_dst = udp_sock.recv_addr.sin_addr;

    // Calculating the IP header checksum
    iph->ip_sum = checksum((unsigned short *) datagram, iph->ip_len);

    // Configuring the UDP header fields
    udph->uh_sport = src_addr.sin_port;
    udph->uh_dport = udp_sock.dest_addr.sin_port;
    udph->uh_ulen = htons(8 + strlen(data)); // UDP header + data
    udph->uh_sum = 0; // Initially zero for checksum

    // Setting up the pseudo-header for UDP checksum calculation
    psh.src_ip = src_addr.sin_addr.s_addr;
    psh.dest_ip = udp_sock.recv_addr.sin_addr.s_addr;
    psh.reserved = 0;
    psh.seg_len = htons(sizeof(struct udphdr) + strlen(data));
    psh.protocol = 17; // UDP protocol

    // Creating the pseudogram for checksum calculation
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = new char[psize];
    memcpy(pseudogram, (char *) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + strlen(data));
    udph->uh_sum = checksum((unsigned short *) pseudogram, psize);

    // Setting the IP_HDRINCL option to include the IP header
    unsigned int one = 1;
    const unsigned int *val = &one;
    if (setsockopt(raw, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        std::cerr << "[solve_evil_port] Error: setsockopt(IP_HDRINCL) failed. (" << strerror(errno) << ")" << std::endl;
        delete[] pseudogram;
        close(raw);
        return false;
    }

    // Calculating the actual packet size
    int packet_size = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);

    // Sending the packet with the evil bit set using the raw socket
    if (sendto(raw, datagram, packet_size, 0, (struct sockaddr *) &udp_sock.dest_addr,
               sizeof(udp_sock.dest_addr)) < 0) {
        std::cerr << "[solve_evil_port] Error: Failed to send packet. (" << strerror(errno) << ")" << std::endl;
        delete[] pseudogram;
        close(raw);
        return false;
    }
    std::cout << "[solve_evil_port] Sent evil bit packet to Port " << port << std::endl;

    // Receiving the response
    memset(recv_buff, 0, sizeof(recv_buff));
    int size = recvfrom(udp_sock.sock, recv_buff, sizeof(recv_buff), 0,
                        (struct sockaddr *) &udp_sock.recv_addr,
                        &rcv_len);
    if (size > 0) {
        // Extracting the last 4 bytes as the evil port
        memcpy(evil_port, &recv_buff[size - 4], 4);
        evil_port[4] = '\0'; // Ensuring null-termination
        std::cout << "[solve_evil_port] Found secret \033[91mEVIL\033[0m port: \033[91m" 
                  << evil_port << "\033[0m" << std::endl << std::endl;
    } else {
        std::cerr << "[solve_evil_port] Error: No response received from the evil port." << std::endl;
    }

    std::cout << "[solve_evil_port] Secret port: " << evil_port << std::endl;

    // Cleaning up dynamically allocated memory and closing the raw socket
    delete[] pseudogram;
    close(raw);

    std::cout << std::endl << "----------------------------------------" << std::endl << std::endl;
    return true;
}

// Function to solve the E.X.P.S.T.N port
bool solve_EXPSTN(socket_handler &udp_sock, char simple_port[], char evil_port[], int oracle_port, char secret_phrase[], uint32_t secret_signature) {
    // Separator for clarity in console output
    std::cout << "----------------------------------------" << std::endl << std::endl;
    std::cout << "\t\tSolving the ORACLE..." << std::endl << std::endl;

    // Preparing the message to send: "evil_port,simple_port"
    char port_send[9] = {0}; // 4 bytes for evil_port, 1 byte for ',', 4 bytes for simple_port
    memcpy(port_send, evil_port, 4);
    port_send[4] = ',';
    memcpy(port_send + 5, simple_port, 4); 

    char recv_buffer[1024] = {0};
    udp_sock.set_port(oracle_port);
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    // Sending the "evil_port,simple_port" message to the oracle (without signature)
    ssize_t sent_len = sendto(udp_sock.sock, port_send, sizeof(port_send), 0, 
                                (struct sockaddr *) &udp_sock.dest_addr, sizeof(udp_sock.dest_addr));
    if (sent_len < 0) {
        std::cerr << "[solve_EXPSTN] Error: sendto failed. (" << strerror(errno) << ")" << std::endl;
        return false;
    }
    std::cout << "[solve_EXPSTN] Sent to Oracle Port " << oracle_port << ": " << port_send << std::endl;

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
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        printf("Usage: ./puzzle_solver <IP address> <port1> <port2> <port3> <port4>\n");
        return -1;
    }

    // Parse command-line arguments
    std::string ip_address = argv[1];
    uint16_t port1 = static_cast<uint16_t>(std::stoi(argv[2])); // Simple port
    uint16_t port2 = static_cast<uint16_t>(std::stoi(argv[3])); // Evil port
    uint16_t port3 = static_cast<uint16_t>(std::stoi(argv[4])); // S.E.C.R.E.T port
    uint16_t port4 = static_cast<uint16_t>(std::stoi(argv[5])); // E.X.P.S.T.N port

    // Create the socket with IP from command line
    socket_handler udp_socket = create_socket(ip_address);

    uint32_t secret_signature = 0;

    char* simple_port = new char[5];
    char* evil_port = new char[5];
    char* secret_phrase = new char[32];

    if (!solve_SECRET(udp_socket, port3, GROUP_NUMBER, GROUP_SECRET, simple_port, secret_signature)) {
        std::cerr << "Failed to solve SECRET port.\n";
        return -1;
    }

    if (!solve_simple_port(udp_socket, port1, secret_signature, secret_phrase)) {
        std::cerr << "Failed to solve the Simple Port.\n";
        return -1;
    }

    if (!solve_evil_port(udp_socket, port2, evil_port, secret_signature)) {
        std::cerr << "Failed to solve the Evil Port.\n";
        return -1;
    };

    if (!solve_EXPSTN(udp_socket, simple_port, evil_port, port4, secret_phrase, secret_signature)) {
        std::cerr << "Failed to solve the ORACLE port.\n";
        return -1;
    }

    // Close the socket
    close(udp_socket.sock);

    return 0;
}