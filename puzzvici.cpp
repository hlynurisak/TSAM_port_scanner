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
#include <algorithm> //for stripping
#include <cctype>   //for stripping

#define BUFFER_SIZE 2048
#define SECRET_PORT 1
#define EVIL_PORT 2
#define CHECKSUM_PORT 3
#define EXPSTN_PORT 4


using namespace std;

 

std::string strip_quotes(const std::string& input) {
    size_t start = 0;
    size_t end = input.length() - 1;

    // Move start to first alphanumeric character
    while (start < input.length() && !isalnum(static_cast<unsigned char>(input[start]))) {
        ++start;
    }

    // Move end to last alphanumeric character
    while (end > start && !isalnum(static_cast<unsigned char>(input[end]))) {
        --end;
    }

    return input.substr(start, end - start + 1);
}

class UDPSocket {
public:
    int sock;
    struct sockaddr_in dest_addr;
    struct sockaddr_in recv_addr;
    socklen_t addr_len;

    UDPSocket() {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            throw std::runtime_error("Error creating UDP socket");
        }
        addr_len = sizeof(struct sockaddr_in);
    }

    ~UDPSocket() {
        close(sock);
    }

    // Method to set the destination port and address
    void set_address(const char *ip_string, uint16_t port) {
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip_string, &dest_addr.sin_addr) <= 0) {
            throw std::runtime_error("Invalid IP address");
        }
    }
    // Method to send data
    ssize_t send_data(const char *buffer, size_t buffer_size) {
        return sendto(sock, buffer, buffer_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    }

    // Method to receive data
    ssize_t receive_data(char *buffer, size_t buffer_size) {
        return recvfrom(sock, buffer, buffer_size, 0, (struct sockaddr *) &recv_addr, &addr_len);
    }

    // Method to set socket timeout
    void set_timeout(int seconds, int microseconds = 0) {
        struct timeval timeout;
        timeout.tv_sec = seconds;
        timeout.tv_usec = microseconds;

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            throw std::runtime_error("Error setting socket timeout");
        }
    }
};


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
bool knock_and_perform(const char *ip_string, uint16_t port, uint32_t signature, uint16_t secret_secret_port, uint16_t secret_evil_port, const string &secret_phrase);
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

    // Loop through all ports to check if they are open and responding, while mapping them to variables
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


    vector<uint16_t> knock_sequence;

    if (knock_and_perform(ip_string, expstn_port, group_signature, secret_secret_port, secret_evil_port, secret_phrase)) {
        cout << "Port knocking and message sending completed successfully." << endl;
    } else {
        cout << "Port knocking or message sending failed." << endl;
    }
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
    ip_hdr->ip_off = (0x8000);   // Evil bit set (Don't Fragment + Evil Bit)
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

bool knock_and_perform(const char *ip_string, uint16_t port, uint32_t signature, uint16_t secret_secret_port, uint16_t secret_evil_port, const string &secret_phrase) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Error creating socket" << endl;
        return false;
    }

    // Set socket timeout using setsockopt
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5-second timeout
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

    // Send secret ports to the oracle
    char secret_ports[10];
    snprintf(secret_ports, sizeof(secret_ports), "%u,%u", secret_secret_port, secret_evil_port);
    ssize_t sent_bytes = sendto(sock, secret_ports, sizeof(secret_ports), 0, 
                                (struct sockaddr *)&server_address, sizeof(server_address));
    if (sent_bytes < 0) {
        perror("Error sending secret ports");
        close(sock);
        return false;
    }

    // Receive the knock sequence
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_address);
    ssize_t recv_bytes = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&server_address, &addr_len);
    if (recv_bytes < 0) {
        perror("Error receiving knock sequence");
        close(sock);
        return false;
    }

    buffer[recv_bytes] = '\0';  // Null-terminate the received string
    string response(buffer);

    // Parse knock sequence
    vector<uint16_t> knock_sequence;
    size_t pos = 0;
    while ((pos = response.find(',')) != string::npos) {
        knock_sequence.push_back(stoi(response.substr(0, pos)));
        response.erase(0, pos + 1);
    }
    knock_sequence.push_back(stoi(response));

    // Perform knocking
    UDPSocket udp_sock;
    udp_sock.set_timeout(5);  // Increased timeout to 5 seconds

    for (size_t port_index = 0; port_index < knock_sequence.size(); ++port_index) {
        uint16_t current_port = knock_sequence[port_index];
        udp_sock.set_address(ip_string, current_port);

        // Prepare the message (signature + secret phrase)

        std::cout << "Before stripping: " << secret_phrase << std::endl;
        std::string stripped_secret_phrase = strip_quotes(secret_phrase); // Ensure quotes are stripped
        std::cout << "After stripping: " << stripped_secret_phrase << std::endl;        
        size_t message_len = stripped_secret_phrase.length();
        uint32_t net_signature = (signature);
        size_t buffer_size = 4 + message_len;
        char* send_buffer_message = new char[buffer_size];

        // Copy the signature (4 bytes) and secret phrase into the send buffer
        memcpy(send_buffer_message, &net_signature, sizeof(net_signature));
        memcpy(send_buffer_message + sizeof(net_signature), stripped_secret_phrase.c_str(), message_len);


        // Print the message in hex before sending
        cout << "Message contents (hex): ";
        for (size_t i = 0; i < buffer_size; ++i) {
            printf("%02X ", (unsigned char)send_buffer_message[i]);
        }
        cout << endl;



        // Send the message
        ssize_t knock_sent_len = udp_sock.send_data(send_buffer_message, buffer_size);
        if (knock_sent_len < 0) {
            cerr << "[perform_port_knocking] Error sending to port " << current_port << endl;
            delete[] send_buffer_message;  // Free allocated memory
            continue;
        }

        // Receive response
        memset(buffer, 0, sizeof(buffer));
        ssize_t knock_recv_len = udp_sock.receive_data(buffer, sizeof(buffer) - 1);

        if (knock_recv_len < 0) {
            perror("[perform_port_knocking] Error receiving from port");
            delete[] send_buffer_message;  // Free allocated memory
            continue;
        }

        // Null-terminate the received data
        buffer[knock_recv_len] = '\0';
        cout << "[perform_port_knocking] Received from Port " << current_port << ": " << buffer << endl;

        // Clean up
        delete[] send_buffer_message;  // Free allocated memory
    }

    close(sock);
    return true;
};
