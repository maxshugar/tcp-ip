#ifndef TCP_IP_STACK_H
#define TCP_IP_STACK_H

#include <arpa/inet.h> // For inet_addr
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// IP and TCP header structures
struct ip_header
{
	unsigned char header_length : 4, version : 4;
	unsigned char type_of_service;
	unsigned short total_length;
	unsigned short identification;
	unsigned short fragment_offset;
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int source_address;
	unsigned int destination_address;
};

struct tcp_header
{
	unsigned short source_port;
	unsigned short destination_port;
	unsigned int sequence_number;
	unsigned int acknowledgment_number;
	unsigned short reserved : 4, data_offset : 4;
	unsigned short flags;
	unsigned short window_size;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

// Pseudo header for TCP checksum calculation
struct pseudo_header
{
	unsigned int source_address;
	unsigned int destination_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};

// Constants
#define PACKET_BUFFER_SIZE 4096
#define IP_VERSION 4
#define IP_HEADER_LENGTH 5	// Header length in 32-bit words
#define TCP_HEADER_LENGTH 5 // Header length in 32-bit words
#define DEFAULT_TTL 255
#define DEFAULT_WINDOW_SIZE 5840
#define PROTOCOL_TCP IPPROTO_TCP
#define SOURCE_IP "127.0.0.1" // Replace with your actual IP
#define DEST_IP "127.0.0.1"	  // Replace with the destination IP
#define DEST_PORT 80		  // Example port

// Function declarations
unsigned short calculate_checksum(void *buffer, int length);
void build_ip_header(struct ip_header *ip, int packet_length, const char *src_ip, const char *dest_ip);
void build_tcp_header(struct tcp_header *tcp, int source_port, int dest_port, unsigned int seq_number);

#endif // TCP_IP_STACK_H
