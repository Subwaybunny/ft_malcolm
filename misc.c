/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   misc.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/21 19:28:05 by jragot            #+#    #+#             */
/*   Updated: 2021/12/13 05:54:12 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"

extern struct project g_project;

int count_token(char token, const char *str)
{
	int i = 0;

	while (*str)
	{
		if (*str == token)
			++i;
		++str;
	}
    return (i);
}

int ft_tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        c += 32;
    return (c);
}

void *ft_memset(void *s, int c, size_t n)
{
	unsigned char *b;

	b = s;
	while (n--)
		*b++ = (unsigned char)c;
	return (s);
}

int	ft_memcmp(const void *s1, const void *s2, size_t n)
{
	unsigned char *t1;
	unsigned char *t2;

	t1 = (unsigned char*)s1;
	t2 = (unsigned char*)s2;
	while (n--)
	{
		if (*t1 != *t2)
			return (*t1 - *t2);
		++t1;
		++t2;
	}
	return (0);
}


void *ft_memcpy(void *dst, const void *src, size_t n)
{
	char		*dst_cpy;
	char		*src_cpy;

	dst_cpy = (char*)dst;
	src_cpy = (char*)src;
	while (n--)
		*dst_cpy++ = *src_cpy++;
	return (dst);
}


int ft_strcmp(const char *s1, const char *s2)
{
    while(*s1 && (*s1 == *s2))
    {
        ++s1;
        ++s2;
    }
    return (*(unsigned char *)s1 - *(unsigned char *)s2);
}

int	isbase16(char c)
{
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		return (1);
	return (0);
}

void exit_error(const char *message)
{
	if (message)
		printf("%s\n", message);
	exit(-1);
}

int	sp_atoi(const char *str, int n)
{
	int i = 0;
    int res = 0; 

	while (i < n && str[i] >= '0' && str[i] <= '9')
	{
		res = res * 10 + (str[i] - '0');
		++i;
	}
    if (!(i || str[i] < '0' || str[i] > '9'))
        res = -1;
    return (res);
}

int is_valid_ipv4(const char *addr)
{
    int i = 0;
    int j = 0;
    int tmp = -1;
    int fields = 0;

    if (count_token('.', addr) != 3)
        return (-1);
    while (addr[i])
    {
        if (!(addr[i] == '.' || (addr[i] >= '0' && addr[i] <= '9')))
            return (-1);
        ++i;
    }
    if (i < 7 || i > 15)
        return (-1);
    i = 0;
    while (addr[j])
    {
        while (addr[j] && addr[j] != '.')
            ++j;
        if (i >= j)
            return (-1);
        tmp = sp_atoi(addr + i, j - i);
        if (tmp < 0 || tmp > 255)
            return (-1);
        else
            ++fields;
        if (!addr[j])
            break;
        ++j;
        i = j;
    }
    return (fields == 4) ? 0 : -1;
}

int is_valid_mac(const char *addr)
{
    int i = 0;

    while (i < 15)
    {
        if (!(isbase16(addr[i]) && isbase16(addr[i + 1]) && addr[i + 2] == ':'))
            return (-1);
        i += 3;
    }
    if (i == 15)
        if (isbase16(addr[i]) && isbase16(addr[i + 1]) && addr[i + 2] == '\0')
            return (0);
    return (-1);
}

void	requirements(int ac, char **av)
{
	g_project.verbose = (ac == 6 && ft_strcmp(av[5], "-v") == 0) ? 1 : 0;
	if (!(ac == 5 || (ac == 6 && g_project.verbose)))
		exit_error("Usage: ft_malcolm <source IP> <source MAC> <target IP> <target MAC> [-v]");
	if (getuid() != 0)
		exit_error("Error: This program must be run as root/sudo user.");
	if (is_valid_ipv4(av[1]) != 0)
		exit_error("Invalid source IP");
	if (is_valid_ipv4(av[3]) != 0)
		exit_error("Invalid target IP");
	if (is_valid_mac(av[2]) != 0)
		exit_error("Invalid source MAC");
	if (is_valid_mac(av[4]) != 0)
		exit_error("Invalid target MAC");
}

char	hextobyte(const char *hex)
{
	/* Translate ASCII value into binary */
	char left = (hex[0] < 'a') ? hex[0] - 48 : hex[0] - 87;
	char right = (hex[1] < 'a') ? hex[1] - 48 : hex[1] - 87;

	/* Join the two values into a single byte */
	return ((left << 4) + right);
}

void	mac_strbin(unsigned char *bin, const char *hex)
{
	ssize_t size = 0;
	char tmp[17] = {0};

	while (size <= 16)
	{
		tmp[size] = ft_tolower(hex[size]);
		++size;
	}
	size = 0;
	while (size < 16)
	{
		if (size % 3 == 0) /* Moving the pointer to hex sequences in the string */
			*bin++ = hextobyte(tmp + size);
		++size;
	}
}

void	print_buffer(unsigned char *buffer, ssize_t buflen)
{
	ssize_t i = 0;

	printf("\n");
	while (i < buflen)
		printf("%02x ", buffer[i++]);
	printf("\n");
}
