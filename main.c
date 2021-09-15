#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>
//#include <sys/types.h>
//#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

//#include <netinet/in.h>
#include <ifaddrs.h>
#include "ft_split.c"
#include "count_tab.c"
#include "ft_putlen.c"
#include "ft_malcolm.h"

void	exit_error(const char *message)
{
	if (message)
		printf("%s\n", message);
	exit(0);				// *** LIBC
}

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

void	requirements(int ac, char **av)
{
	if (ac != 2)
		exit_error("Usage: ft_malcolm [host]");
	if (getuid() != 0)
		exit_error("Error: This program must be run as root/sudo user.");
	if (is_valid_ipv4(av[1]) != 0)
		exit_error("Invalid source IP (numbers-and-dots check)");
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

void	print_raw_data(unsigned char *buffer)
{
	printf("-----------------------\n");
	while (*buffer)
		printf("%1x", *buffer++);
	printf("\n-----------------------\n");
}

/*
void	print_headers(unsigned char *buffer)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	printf("\nEthernet Header\n");
	printf("|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	printf("|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	printf("|-Protocol : %04x\n",ntohs(eth->h_proto));
	if (ntohs(eth->h_proto) == ETH_P_ARP)
		printf("*** ARP PACKET ***\n");
	if (ntohs(eth->h_proto) == ETH_P_IP)
		printf("*** IP PACKET ***\n");
	print_raw_data(buffer);
}
*/

//void	print_arp(unsigned char*, ssize_t, int);

void	print_buffer(unsigned char *buffer, ssize_t buflen)
{
	ssize_t i = 0;

	printf("\n");
	while (i < buflen)
		printf("%02x ", buffer[i++]);
	printf("\n");
}

unsigned char	*craft_arp(const char *sip, unsigned char *raw_arp)
{
//	struct ethhdr frame;
	struct arp_ip packet;
	in_addr_t sender = inet_addr(sip);

	bzero(&packet, sizeof(struct arp_ip));			// *** LIBC
	memcpy(packet.ar_sip, &sender, sizeof(in_addr_t));	// *** LIBC
	memcpy(raw_arp, &packet, 28);				// *** LIBC
	return (raw_arp);
}

void	process_arp(unsigned char *buffer, ssize_t buflen)
{
	struct arp_ip *arp = (struct arp_ip *)(buffer); /* We create this structure specific to IP protocol for later */
	printf("(%ld bytes read from socket)\n----ARP PAYLOAD----:\n", buflen);

	buffer += sizeof(struct arphdr);
	printf("|-Sender HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	buffer += arp->ar_hln;
	printf("|-Sender IP address: %d.%d.%d.%d\n", buffer[0], buffer[1], buffer[2], buffer[3]);
	buffer += arp->ar_pln;
	printf("|-Target HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	buffer += arp->ar_hln;
	printf("|-Target IP address: %d.%d.%d.%d\n", buffer[0], buffer[1], buffer[2], buffer[3]);
	printf("\n");
//	pos += arp->ar_hln;


//	unsigned char *verif = (unsigned char *)arp;
//	printf("strlen verif: %d\n", strlen((const char*)verif));
//	print_arp(verif, buflen, 1);
}


/*
void	print_arp(unsigned char *buffer, ssize_t buflen)
{
	struct arphdr *arp = (struct arphdr *)(buffer);

	printf("ARP Packet (%d bytes)\n", buflen-(sizeof(struct arphdr)));
	printf("ar_hrd: %02x\n", arp->ar_hrd);
	printf("ar_pro: %02x\n", arp->ar_pro);
	printf("ar_hln: %02x\n", arp->ar_hln);
	printf("ar_pln: %02x\n", arp->ar_pln);
	printf("ar_op: %02x\n", arp->ar_op);

	buffer += sizeof(struct arphdr);
	printf("|-Sender HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	buffer += arp->ar_hln;
	printf("|-Sender IP address: %d.%d.%d.%d\n", buffer[0], buffer[1], buffer[2], buffer[3]);
	buffer += arp->ar_pln;
	printf("|-Target HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	buffer += arp->ar_hln;
	printf("|-Target IP address: %d.%d.%d.%d\n", buffer[0], buffer[1], buffer[2], buffer[3]);
	printf("\n");
//	pos += arp->ar_hln;


//	unsigned char *verif = (unsigned char *)arp;
//	printf("strlen verif: %d\n", strlen((const char*)verif));
//	print_arp(verif, buflen, 1);
}*/

/*
void	print_arp(unsigned char *buffer, ssize_t buflen, int stop)
{
	ssize_t i = 0;
//	unsigned short arp_hdr_len = 0;
//	struct arphdr *arp = (struct arphdr*)(buffer + sizeof(struct arphdr));

//	i = sizeof(struct ethhdr) + 1;
	printf("---------------\n");
	while (i < buflen)
		printf("%02x ", buffer[i++]);
	printf("\n---------------\n");
	if (stop == 0)
		jesaispas(buffer+sizeof(struct ethhdr), buflen-sizeof(struct ethhdr));
}
*/

void	process_ethernet(unsigned char *buffer, ssize_t buflen)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);

	if (ntohs(eth->h_proto) == ETH_P_ARP)
	{
		printf("\n*** ARP PACKET ***\n");
		printf("\nEthernet Header\n");
		printf("|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
		printf("|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		printf("|-Protocol : %04x\n",ntohs(eth->h_proto));
		printf("Raw bits received:");
		print_buffer(buffer, buflen);
		process_arp(buffer+sizeof(struct ethhdr), buflen);
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
	unsigned char buffer[65536];
//	unsigned char raw_arp[28];

//	in_addr_t	source_ip = 0;
//	in_addr_t	target_ip = 0;

//	if ((source_ip = inet_addr(av[1]) == INADDR_NONE))
//		exit_error("Invalid source IP");
//	if ((target_ip = inet_addr(av[3]) == INADDR_NONE))
//		exit_error("Invalid target IP");
//	if ((host = gethost(av[1])) != NULL)
//		printf("Host: %s\n", host->h_name);
	requirements(ac, av);

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
