#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
//#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

//#include <netinet/in.h>
#include <ifaddrs.h>
#include "ft_split.c"
#include "count_tab.c"

void	exit_error(const char *message)
{
	if (message)
		printf("%s\n", message);
	exit(0);
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
		if (!(strlen(*tab) && strlen(*tab) <= 3))
			return (-2);
		i = 0;
		while (tab[i])
			if (!(isdigit(*tab[i++])))
				return (-3);
		if (atoi(*tab) < 0 || atoi(*tab) > 255)
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

struct ifaddrs *getinterface(struct ifaddrs *iflist, char *name)
{
	while (iflist)
	{
		if (strcmp(iflist->ifa_name, name) == 0)
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

int	main(int ac, char **av)
{
	int fd;
//	struct hostent *host = NULL;
	struct ifaddrs *iflist = NULL;
	struct ifaddrs *interface = NULL;
	unsigned char buffer[65536];
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
		perror("error");
	if ((getifaddrs(&iflist) < 0))
		exit_error("Error: Failed to fetch interfaces");
	if ((interface = getinterface(iflist, "eth0")))
		printf("interface name is %s\n", interface->ifa_name);
//	int setsockopt(fd, SOL_SOCKET, int optname, const void *optval, socklen_t optlen)
	printf("socket is %d\n", fd);

	memset(buffer, 0, 65536);
	struct sockaddr saddr;
	int saddr_len = sizeof(saddr);
	ssize_t buflen = 0;

	buflen=recvfrom(fd,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);
	if (buflen < 0)
	{
		printf("error in reading recvfrom function\n");
		return (-1);
	}
	print_headers(buffer);

	/* Clean up */
	(close(fd)) != 0 ? printf("Error closing socket\n") : 0;
	if (iflist)
		freeifaddrs(iflist);
	return (0);
}
