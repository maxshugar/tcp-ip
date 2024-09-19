#include "tcp_ip_stack.h"

// Function to calculate checksum (a necessary step in IP and TCP headers to ensure packet integrity)
// The checksum ensures that the header information is not corrupted during transmission
unsigned short calculate_checksum(void *buffer, int length)
{
	unsigned short *buf = buffer; // Treat the buffer as an array of 16-bit unsigned shorts
	unsigned int sum = 0;		  // Sum will accumulate the header values for checksum
	unsigned short result;

	// Sum each 16-bit word in the buffer
	for (sum = 0; length > 1; length -= 2)
	{
		sum += *buf++;
	}

	// If there's a remaining byte (in case of odd length), add it
	if (length == 1)
	{
		sum += *(unsigned char *)buf;
	}

	// Add overflowed bits from the sum
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	// One's complement of the sum gives us the final checksum
	result = ~sum;
	return result;
}

// Function to build the IP header
// This is the part of the packet that handles network-level (Layer 3) addressing (source, destination IPs)
void build_ip_header(struct ip_header *ip, int packet_length, const char *src_ip, const char *dest_ip)
{
	ip->version = IP_VERSION;					  // Set IP version to 4 (IPv4)
	ip->header_length = IP_HEADER_LENGTH;		  // IP header length (in 32-bit words), usually 5 (which equals 20 bytes)
	ip->type_of_service = 0;					  // Type of service, generally set to 0
	ip->total_length = htons(packet_length);	  // Total length of the IP packet (header + data)
	ip->identification = htons(54321);			  // Unique ID for the packet (arbitrary for now)
	ip->fragment_offset = 0;					  // No fragmentation
	ip->time_to_live = DEFAULT_TTL;				  // TTL (how long a packet can live before it's discarded)
	ip->protocol = PROTOCOL_TCP;				  // Protocol type, in this case, TCP (which is protocol number 6)
	ip->source_address = inet_addr(src_ip);		  // Source IP address (this is your machine's IP)
	ip->destination_address = inet_addr(dest_ip); // Destination IP address (the target machine)
	ip->checksum = 0;							  // Initially set to 0 before calculating checksum

	// Calculate the IP header checksum
	ip->checksum = calculate_checksum((unsigned short *)ip, sizeof(struct ip_header));
}

// Function to build the TCP header
// TCP is the transport layer (Layer 4), managing port-to-port communication and connection control (handshakes, etc.)
void build_tcp_header(struct tcp_header *tcp, int source_port, int dest_port, unsigned int seq_number)
{
	tcp->source_port = htons(source_port);		   // Source port (use any arbitrary port, e.g., 12345)
	tcp->destination_port = htons(dest_port);	   // Destination port (e.g., HTTP on port 80)
	tcp->sequence_number = htonl(seq_number);	   // Sequence number (important for ordering TCP segments)
	tcp->acknowledgment_number = 0;				   // Not used initially (we're not acknowledging anything yet)
	tcp->data_offset = TCP_HEADER_LENGTH;		   // TCP header length (in 32-bit words), typically 5 (which equals 20 bytes)
	tcp->flags = htons(0x02);					   // Set the SYN flag (this starts the TCP handshake)
	tcp->window_size = htons(DEFAULT_WINDOW_SIZE); // Window size (the amount of data that can be sent without acknowledgment)
	tcp->checksum = 0;							   // Initially set to 0 before calculating the checksum
	tcp->urgent_pointer = 0;					   // Not using urgent data
}