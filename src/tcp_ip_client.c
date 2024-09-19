#include "tcp_ip_stack.h"

// Main function: This sets up a raw TCP packet, sends it to the destination, and initiates a TCP handshake
int main()
{
	// Step 1: Create a raw socket for sending TCP packets directly (bypassing the kernel's TCP stack)
	int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (raw_socket < 0)
	{
		// If socket creation fails, print an error message and exit
		perror("Socket creation failed");
		return 1;
	}

	// Step 2: Define the destination address (where we are sending the packet)
	struct sockaddr_in destination;
	destination.sin_family = AF_INET;				  // Use IPv4 addressing
	destination.sin_port = htons(DEST_PORT);		  // Set the destination port (in this case, HTTP's port 80)
	destination.sin_addr.s_addr = inet_addr(DEST_IP); // Set the destination IP address

	// Step 3: Create a packet buffer to hold both IP and TCP headers
	char packet[PACKET_BUFFER_SIZE];
	memset(packet, 0, PACKET_BUFFER_SIZE); // Clear the packet buffer (set all bytes to 0)

	// Step 4: Build the IP and TCP headers in the packet buffer
	struct ip_header *ip = (struct ip_header *)packet;								   // IP header starts at the beginning of the packet buffer
	struct tcp_header *tcp = (struct tcp_header *)(packet + sizeof(struct ip_header)); // TCP header starts after the IP header

	// Call helper functions to build IP and TCP headers
	build_ip_header(ip, sizeof(struct ip_header) + sizeof(struct tcp_header), SOURCE_IP, DEST_IP);
	build_tcp_header(tcp, 12345, DEST_PORT, 0); // Random source port and sequence number (sequence number is 0 for now)

	// Step 5: Create a pseudo header (used in TCP checksum calculation)
	// The pseudo header includes the IP source and destination addresses, the protocol, and TCP length.
	// It's used to ensure that the TCP checksum takes into account the relevant IP data as well.
	struct pseudo_header psh;
	psh.source_address = inet_addr(SOURCE_IP);		   // Source IP address
	psh.destination_address = inet_addr(DEST_IP);	   // Destination IP address
	psh.placeholder = 0;							   // Placeholder is always 0
	psh.protocol = PROTOCOL_TCP;					   // Protocol is TCP
	psh.tcp_length = htons(sizeof(struct tcp_header)); // Length of the TCP header

	// Combine the pseudo header and TCP header for the checksum calculation
	int pshdr_len = sizeof(struct pseudo_header) + sizeof(struct tcp_header);
	char pshdr[pshdr_len];
	memcpy(pshdr, &psh, sizeof(struct pseudo_header));							  // Copy the pseudo header into the buffer
	memcpy(pshdr + sizeof(struct pseudo_header), tcp, sizeof(struct tcp_header)); // Append the TCP header

	// Calculate the TCP checksum
	tcp->checksum = calculate_checksum((unsigned short *)pshdr, pshdr_len);

	// Step 6: Send the packet
	// `sendto()` sends the raw packet to the specified destination (IP address and port)
	if (sendto(raw_socket, packet, ntohs(ip->total_length), 0, (struct sockaddr *)&destination, sizeof(destination)) < 0)
	{
		// If sending fails, print an error message
		perror("Packet send failed");
	}
	else
	{
		// If sending succeeds, notify the user
		printf("SYN packet sent successfully!\n");
	}

	// Step 7: Clean up by closing the socket
	close(raw_socket);
	return 0;
}
