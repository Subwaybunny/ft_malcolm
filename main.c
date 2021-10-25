/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:21:52 by jragot            #+#    #+#             */
/*   Updated: 2021/10/25 19:55:43 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"

struct addr_set g_addresses;

struct hostent *gethost(const char *name)
{
	struct hostent *host = NULL;
	if ((host = gethostbyname(name)) != NULL)
		return (host);
	else
		printf("Error: %s is not a valid hostname\n", name);
	return (NULL);
}

struct ifaddrs *getinterface(struct ifaddrs *iflist,const char *name)
{
	while (iflist)
	{
		if (strcmp(iflist->ifa_name, name) == 0) // *** LIBC
			return (iflist);
		iflist = iflist->ifa_next;
	}
	return (NULL);
}

/* unsigned char	*craft_arp(const char *sip, unsigned char *output)
{
	struct ethhdr frame;
	struct arp_ip packet;
	in_addr_t sender = inet_addr(sip);
	
	memset(&frame, 0, sizeof(frame));			// *** LIBC
	memset(&packet, 0, sizeof(packet));			// *** LIBC
	memcpy(packet.ar_sip, &sender, sizeof(sender));	// *** LIBC
	memcpy(frame.h_dest, "\x0a\x0b\x0c\x0d\x0e\x0f", 6); // *** LIBC
	memcpy(frame.h_source, "\x42\x41\x42\x41\x42\x41", 6); // *** LIBC
	memcpy(&frame.h_proto, "\x08\x06", 2);		// *** LIBC
	memcpy(packet.ar_hrd, "\x00\x01", 2);
	memcpy(packet.ar_pro, "\x08\x00", 2);
	packet.ar_hln = 6;
	packet.ar_pln = 4;
	memcpy(packet.ar_op, "\x00\x03", 2);
	memcpy(packet.ar_sha, "\x41\x42\x41\x42\x41\x42", 6);
	memcpy(packet.ar_sip, &sender, 2);
//	memcpy(packet.ar_hrd, "\x00\x01", 2);
	memcpy(output, &frame, 28);					// *** LIBC
	memcpy(output+sizeof(frame), &packet, sizeof(packet));
	return (output);
} 

void	print_addr_set(struct addr_set addresses)
{
	printf("-------\nSIP: %.2x.%.2x.%.2x.%.2x\n-------\n", addresses.sip[0], addresses.sip[1], addresses.sip[2], addresses.sip[3]);
	printf("-------\nTIP: %.2x.%.2x.%.2x.%.2x\n-------\n", addresses.tip[0], addresses.tip[1], addresses.tip[2], addresses.tip[3]);

}*/

unsigned char	*craft_arp(unsigned char *output)
{
//	print_addr_set(g_addresses);
	struct ethhdr frame;
	struct arp_ip packet;
	
	memset(&frame, 0, sizeof(frame));			// *** LIBC
	memset(&packet, 0, sizeof(packet));			// *** LIBC
	memcpy(frame.h_dest, g_addresses.tmac, 6); // *** LIBC
	memcpy(frame.h_source, g_addresses.smac, 6); // *** LIBC
	memcpy(&frame.h_proto, "\x08\x06", 2);		// *** LIBC
	memcpy(packet.ar_hrd, "\x00\x01", 2);
	memcpy(packet.ar_pro, "\x08\x00", 2);
	packet.ar_hln = 6;
	packet.ar_pln = 4;
	memcpy(packet.ar_op, "\x00\x02", 2); // ARP REPLY OPCODE
	memcpy(packet.ar_sha, g_addresses.smac, 6);
	memcpy(packet.ar_sip, &g_addresses.sip, 4);
	memcpy(packet.ar_tha, g_addresses.tmac, 6);
	memcpy(packet.ar_tip, &g_addresses.tip, 4);
	memcpy(output, &frame, 28);					// *** LIBC
	memcpy(output+sizeof(frame), &packet, sizeof(packet));
	return (output);
}

void	arp_reply(struct arp_ip *request) // Maybe we can remove the function parameter
{
	unsigned char output[42];
	printf("(ARP REQUEST DETECTED FROM %d.%d.%d.%d)\n", request->ar_sip[0], request->ar_sip[1], request->ar_sip[2], request->ar_sip[3]);
	craft_arp(output);
	printf("------ REPLYING: ------\n");
	process_ethernet(output, 42);
	printf("------------------------------------\n");
}

void	process_arp(unsigned char *buffer, ssize_t buflen)
{
	struct arp_ip *arp = (struct arp_ip *)(buffer); /* We create this structure specific to IP protocol for later */
	printf("(%d bytes read from socket)\n----ARP PAYLOAD----:\n", (unsigned int)buflen);

	buffer += sizeof(struct arphdr);
	printf("\nSIZE OF ETH STRUCT: %d", sizeof(struct ethhdr));
	printf("\nSIZE OF ARP STRUCT: %d\n", sizeof(struct arphdr));
	printf("|-Sender HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	buffer += arp->ar_hln;
	printf("|-Sender IP address: %d.%d.%d.%d\n", buffer[0], buffer[1], buffer[2], buffer[3]);
	buffer += arp->ar_pln;
	printf("|-Target HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	buffer += arp->ar_hln;
	printf("|-Target IP address: %d.%d.%d.%d\n", buffer[0], buffer[1], buffer[2], buffer[3]);
	buffer += arp->ar_pln;
	printf("|- OPcode: %.2x:%.2x\n", arp->ar_op[0], arp->ar_op[1]);
	if (arp->ar_op[0] == 0 && arp->ar_op[1] == 1) /* We check if this is an ARP REQUEST */
		if (ntohs(inet_addr((char *)arp->ar_sip)) == g_addresses.tip) // NEED TO FIX THIS*************
			arp_reply(arp);
}

void	process_ethernet(unsigned char *buffer, ssize_t buflen)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);

//	printf("\nprc_eth called with buflen=%d", buflen);
	if (ntohs(eth->h_proto) == ETH_P_ARP)
	{
		printf("\n*** ARP PACKET ***\n");
		printf("\nEthernet Header\n");
		printf("|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
		printf("|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		printf("|-Protocol : %04x\n",ntohs(eth->h_proto));
		printf("Raw bits received:");
		print_buffer(buffer, buflen);
		process_arp(buffer+sizeof(struct ethhdr), buflen); // Don't forget to remove header size from buflen
	}
	else
		printf(".");
}

int	main(int ac, char **av)
{
	int fd;
//	struct hostent *host = NULL;
	struct ifaddrs *iflist = NULL;
	struct ifaddrs *interface = NULL;
//	struct addr_set addresses; MOVED TO A GLOBAL VARIABLE
	unsigned char buffer[65536];
// 	unsigned char output[42];  (MOVED)

//	in_addr_t	source_ip = 0;
//	in_addr_t	target_ip = 0;

//	if ((source_ip = inet_addr(av[1]) == INADDR_NONE))
//		exit_error("Invalid source IP");
//	if ((target_ip = inet_addr(av[3]) == INADDR_NONE))
//		exit_error("Invalid target IP");
//	if ((host = gethost(av[1])) != NULL)
//		printf("Host: %s\n", host->h_name);
	requirements(ac, av);

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		exit_error("Could not catch signal\n");
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("error");		// *** LIBC
	if ((getifaddrs(&iflist) < 0))
		exit_error("Error: Failed to fetch interfaces");
	if ((interface = getinterface(iflist, "eth0")))
		printf("interface name is %s\n", interface->ifa_name);
//	int setsockopt(fd, SOL_SOCKET, int optname, const void *optval, socklen_t optlen)
	printf("socket is %d\n", fd);

	memset(buffer, 0, 65536);		// *** LIBC
	struct sockaddr saddr;
	int saddr_len = sizeof(saddr);
	ssize_t buflen = 0;

/* HERE CHECK THAT MAC AND IP ARE VALID (maybe already done in requirements() */
	memset(&g_addresses, 0, sizeof(g_addresses)); // *** LIBC
	g_addresses.sip = inet_addr(av[1]);
	feed_bin(g_addresses.smac, av[2]);
	g_addresses.tip = inet_addr(av[3]);
	feed_bin(g_addresses.tmac, av[4]);
	//(MOVED TO arp_reply) craft_arp(addresses, output); // JUST FOR TEST ?
	//(MOVED TO arp_reply) process_ethernet(output, 42); // JUST FOR TEST ?
	while (1)
	{
		buflen = recvfrom(fd, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
		if (buflen < 0)
			exit_error("Failed to read from socket");
		process_ethernet(buffer, buflen);
	}
//	bzero(raw_arp, 28);
//	printf("\n BEFORE: ");
//	print_buffer(raw_arp, 28);
//	printf("\n AFTER: ");
//	print_buffer(craft_arp(av[1], raw_arp), 28);
	/* Clean up */
	(close(fd)) != 0 ? printf("Error closing socket\n") : 0;
	if (iflist)
		freeifaddrs(iflist);
	return (0);
}
