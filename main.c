/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:21:52 by jragot            #+#    #+#             */
/*   Updated: 2021/12/13 05:54:27 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"

struct project g_project;

void sig_handler(int sig)
{
  if (sig == SIGINT)
  {
	if (g_project.iflist)
		freeifaddrs(g_project.iflist);
	close(g_project.fd);
	exit_error("\nKeyboard Interrupt");
  }
}

int	main(int ac, char **av)
{
	struct ifaddrs *interface = NULL;
	unsigned char buffer[1500];
	ssize_t buflen = 0;
	struct sockaddr saddr;
	int saddr_len = sizeof(saddr);

	g_project.waiting_for_reply = 1;
	g_project.iflist = NULL;
	g_project.fd = -1;

	requirements(ac, av);

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		exit_error("Could not catch signal\n");
	if ((g_project.fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		exit_error("Error opening a socket");
	if ((getifaddrs(&g_project.iflist) < 0))
		exit_error("Error: Failed to fetch interfaces");
	if ((interface = getinterface(g_project.iflist, "wlan0"))) // Check this before submitting project
		printf("Working on interface %s.\n", interface->ifa_name);
	ft_memset(buffer, 0, sizeof(buffer));
	ft_memset(&g_project.addresses, 0, sizeof(g_project.addresses));
	g_project.addresses.sip = inet_addr(av[1]);
	mac_strbin(g_project.addresses.smac, av[2]);
	g_project.addresses.tip = inet_addr(av[3]);
	mac_strbin(g_project.addresses.tmac, av[4]);
	while (g_project.waiting_for_reply)
	{
		buflen = recvfrom(g_project.fd, buffer, sizeof(buffer), 0, &saddr, (socklen_t *)&saddr_len);
		if (buflen < 0)
			exit_error("Failed to read from socket");
		process_ethernet(buffer, buflen);
	}
	/* Clean up */
	(close(g_project.fd)) != 0 ? printf("Error closing socket\n") : 0;
	if (g_project.iflist)
		freeifaddrs(g_project.iflist);
	return (0);
}
