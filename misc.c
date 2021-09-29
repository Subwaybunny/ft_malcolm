/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   misc.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/21 19:28:05 by jragot            #+#    #+#             */
/*   Updated: 2021/09/29 15:40:11 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"

void sig_handler(int sig)
{
  if (sig == SIGINT)
  {
    printf("\nhandling SIGINT\n");
    exit_error("TEMPORARY EXIT");
  }
}

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

int     is_valid_mac(const char *addr)
{
        char **tab = NULL;
        int i = 0;

        tab = ft_split(addr, ':');
	if (strlen(addr) != 17)		// LIBC
		return (-1);
        if (count_tab(tab) != 6)
                return (-2);
        while (*tab)
        {
                if (!(strlen(*tab) && strlen(*tab) == 2))	// LIBC
                        return (-3);
                i = 0;
                while (tab[i])
                        if (!(isbase16(*tab[i++])))
                                return (-4);
                ++tab;
        }
        return (0);
}

void	requirements(int ac, char **av)
{
	if (ac != 5)
		exit_error("Usage: ft_malcolm <source IP> <source MAC> <target IP> <target MAC>");
	if (getuid() != 0)
		exit_error("Error: This program must be run as root/sudo user.");
	if (is_valid_ipv4(av[1]) != 0)
		exit_error("Invalid source IP (numbers-and-dots check)");
	if (is_valid_ipv4(av[3]) != 0)
		exit_error("Invalid target IP (numbers-and-dots check)");
	if (is_valid_mac(av[2]) != 0)
		exit_error("Invalid source MAC");
	if (is_valid_mac(av[4]) != 0)
		exit_error("Invalid target MAC");
}

void	print_raw_data(unsigned char *buffer)
{
	printf("-----------------------\n");
	while (*buffer)
		printf("%1x", *buffer++);
	printf("\n-----------------------\n");
}

void	print_buffer(unsigned char *buffer, ssize_t buflen)
{
//	printf("\nprint_buffer called with buflen=%d", buflen);
	ssize_t i = 0;

	printf("\n");
	while (i < buflen)
		printf("%02x ", buffer[i++]);
	printf("\n");
}