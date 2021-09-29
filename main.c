/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:21:52 by jragot            #+#    #+#             */
/*   Updated: 2021/09/29 05:13:42 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"

int	is_valid_ipv4(const char *addr)
{
	char **tab = NULL;
	int i = 0;

	tab = ft_split(addr, '.');
	if (count_tab(tab) != 4)
		return (-1);
	while (*tab)
	{
		if (!(strlen(*tab) && strlen(*tab) <= 3)) // *** LIBC
			return (-2);
		i = 0;
		while (tab[i])
			if (!(isdigit(*tab[i++])))	// *** LIBC
				return (-3);
		if (atoi(*tab) < 0 || atoi(*tab) > 255) // *** LIBC
			return (-4);
		++tab;
	}
	return (0);
}

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
} */

unsigned char	*craft_arp(struct addr_set addresses, unsigned char *output)
{
	struct ethhdr frame;
	struct arp_ip packet;
	
	memset(&frame, 0, sizeof(frame));			// *** LIBC
	memset(&packet, 0, sizeof(packet));			// *** LIBC
	memcpy(frame.h_dest, addresses.tmac, 6); // *** LIBC
	memcpy(frame.h_source, addresses.smac, 6); // *** LIBC
	memcpy(&frame.h_proto, "\x08\x06", 2);		// *** LIBC
	memcpy(packet.ar_hrd, "\x00\x01", 2);
	memcpy(packet.ar_pro, "\x08\x00", 2);
	packet.ar_hln = 6;
	packet.ar_pln = 4;
	memcpy(packet.ar_op, "\x00\x03", 2);
	memcpy(packet.ar_sha, addresses.smac, 6);
	memcpy(packet.ar_sip, &addresses.sip, 2);
	memcpy(packet.ar_tha, addresses.tmac, 2);
	memcpy(packet.ar_tip, &addresses.tip, 2);
	memcpy(output, &frame, 28);					// *** LIBC
	memcpy(output+sizeof(frame), &packet, sizeof(packet));
	return (output);
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
	printf("\n");
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
	struct addr_set addresses;
	unsigned char buffer[65536];
	unsigned char output[42];

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
	memset(&addresses, 0, sizeof(addresses));
	addresses.sip = inet_addr(av[1]);
	feed_bin(addresses.smac, av[2]);
	addresses.tip = inet_addr(av[3]);
	feed_bin(addresses.tmac, av[4]);
	craft_arp(addresses, output);
	process_ethernet(output, 42);
	printf("------------------------------------\n");
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
