# include <stdio.h>
# include <unistd.h>
# include <string.h>
# include <ctype.h>
# include <stdlib.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <net/ethernet.h>
# include <net/if_arp.h>

/* void	print_buffer(unsigned char *buffer, ssize_t buflen)
{
	ssize_t i = 0;

	printf("\n");
	while (i < buflen)
		printf("%02x ", buffer[i++]);
	printf("\n");
}*/

void	process_ethernet(unsigned char *buffer)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);

	if (ntohs(eth->h_proto) == ETH_P_ARP)
	{
		printf("\n*** ARP PACKET ***\nRaw frame:");
	//	print_buffer(buffer, buflen);
		printf("\n----ETHERNET HEADER:----\n");
		printf("|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		printf("|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	//	printf("|-Protocol : %04x\n",ntohs(eth->h_proto));
	}
}

int	main()
{
	int fd;
	unsigned char buffer[65536];
	struct sockaddr saddr;
	int saddr_len = sizeof(saddr);
	ssize_t buflen = 0;
 //	unsigned char output[42] = {0};  //(MOVED)

	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		perror("error");

	memset(buffer, 0, 65536);

	while (1)
	{
		buflen = recvfrom(fd, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
		if (buflen < 0)
			exit(0);
		process_ethernet(buffer);
	}
	/* Clean up */
	(close(fd)) != 0 ? printf("Error closing socket\n") : 0;
	return (0);
}
