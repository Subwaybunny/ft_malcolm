/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:21:14 by jragot            #+#    #+#             */
/*   Updated: 2021/11/02 01:42:38 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"

int	isbase16(char c)
{
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
		return (1);
	return (0);
}

char	hextobyte(const char *hex)
{
	/* Translate ASCII value into binary */
	char left = (hex[0] < 'a') ? hex[0] - 48 : hex[0] - 87;
	char right = (hex[1] < 'a') ? hex[1] - 48 : hex[1] - 87;

	/* Join the two values into a single byte */
	return ((left << 4) + right);
}

void	feed_bin(unsigned char *bin, const char *hex)
{
	ssize_t size = 17;
	unsigned char tmp[17];
	char **tab = NULL;

	bzero(tmp, 17);		// LIBC
	while (size)
	{
		tmp[size] = tolower(hex[size]); // LIBC
		--size;
	}
	tab = ft_split(hex, ':');
	while (*tab)
		*bin++ = hextobyte(*tab++);
}

void	print_mac(unsigned char *bin)
{
	printf("MAC address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", bin[0], bin[1], bin[2], bin[3], bin[4], bin[5]);
}
