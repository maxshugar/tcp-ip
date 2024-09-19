#include "tcp_ip_stack.h"

// Function to build and send a SYN-ACK packet in response to a SYN
void send_syn_ack(int sock, struct sockaddr_in *client_addr, int client_addr_len, struct ip_header *ip, struct tcp_header *tcp)
{
	char packet[PACKET_BUFFER_SIZE];
	memset(packet, 0, PACKET_BUFFER_SIZE);

	// Pointers to IP and TCP headers in the packet buffer
	struct ip_header *ip_reply = (struct ip_header *)packet;
	struct tcp_header *tcp_reply = (struct tcp_header *)(packet + sizeof(struct ip_header));

	// Build IP header for the SYN-ACK packet
	build_ip_header(ip_reply, sizeof(struct ip_header) + sizeof(struct tcp_header),
					inet_ntoa(client_addr->sin_addr), SOURCE_IP);

	// Build TCP header for the SYN-ACK packet
	build_tcp_header(tcp_reply, ntohs(tcp->destination_port), ntohs(tcp->source_port), 0);
	tcp_reply->acknowledgment_number = htonl(ntohl(tcp->sequence_number) + 1); // Acknowledge the client's SYN
	tcp_reply->flags = htons(0x12);											   // Set SYN and ACK flags

	// Create pseudo header for checksum calculation
	struct pseudo_header psh;
	psh.source_address = ip_reply->source_address;
	psh.destination_address = ip_reply->destination_address;
	psh.placeholder = 0;
	psh.protocol = PROTOCOL_TCP;
	psh.tcp_length = htons(sizeof(struct tcp_header));

	// Combine pseudo header and TCP header to calculate the TCP checksum
	int pshdr_len = sizeof(struct pseudo_header) + sizeof(struct tcp_header);
	char pshdr[pshdr_len];
	memcpy(pshdr, &psh, sizeof(struct pseudo_header));
	memcpy(pshdr + sizeof(struct pseudo_header), tcp_reply, sizeof(struct tcp_header));

	// Set the TCP checksum
	tcp_reply->checksum = calculate_checksum((unsigned short *)pshdr, pshdr_len);

	// Send the SYN-ACK packet back to the client
	if (sendto(sock, packet, ntohs(ip_reply->total_length), 0, (struct sockaddr *)client_addr, client_addr_len) < 0)
	{
		perror("SYN-ACK send failed");
	}
	else
	{
		printf("SYN-ACK packet sent successfully!\n");
	}
}

// Main function: This sets up the server to listen for incoming SYN packets and respond with SYN-ACK
int main()
{
	// Step 1: Create a raw socket to receive incoming TCP packets (SYN packets from clients)
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("Socket creation failed");
		return 1;
	}

	printf("Server is listening for incoming SYN packets...\n");

	// Step 2: Set up the server to listen on a specific port and IP address
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	// Create a buffer to store the incoming packets
	char buffer[PACKET_BUFFER_SIZE];
	memset(buffer, 0, PACKET_BUFFER_SIZE);

	// Step 3: Enter a loop to continuously listen for packets
	while (1)
	{
		// Receive packets from the network
		ssize_t data_len = recvfrom(sock, buffer, PACKET_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len);
		if (data_len < 0)
		{
			perror("Packet receive failed");
			continue;
		}

		// Step 4: Extract the IP and TCP headers from the received packet
		struct ip_header *ip = (struct ip_header *)buffer;
		struct tcp_header *tcp = (struct tcp_header *)(buffer + sizeof(struct ip_header));

		// Check if the packet is a SYN packet (SYN flag should be set and ACK flag should not be set)
		if (tcp->flags & htons(0x02) && !(tcp->flags & htons(0x10)))
		{
			printf("Received SYN packet from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(tcp->source_port));

			// Step 5: Respond to the SYN packet with a SYN-ACK
			send_syn_ack(sock, &client_addr, client_addr_len, ip, tcp);
		}
	}

	// Step 6: Close the socket when done
	close(sock);
	return 0;
}
