#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ft_split.c"
#include "count_tab.c"

int	isbase16(char c)
{
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
		return (1);
	return (0);
}

int     is_valid_mac(const char *addr)
{
        char **tab = NULL;
        int i = 0;

        tab = ft_split(addr, ':');
	if (strlen(addr) != 17)
		return (-1);
        if (count_tab(tab) != 6)
                return (-2);
        while (*tab)
        {
                if (!(strlen(*tab) && strlen(*tab) == 2))
                        return (-3);
                i = 0;
                while (tab[i])
                        if (!(isbase16(*tab[i++])))
                                return (-4);
                ++tab;
        }
        return (0);
}

char	hextobyte(const char *hex)
{
//	printf("\nhex value: %s", hex);
	/* Translate ASCII value into binary */
	char left = (hex[0] < 'a') ? hex[0] - 48 : hex[0] - 87;
	char right = (hex[1] < 'a') ? hex[1] - 48 : hex[0] - 87;

	/* Join the two values into a single byte */
//	printf("\ncurrent byte:  %02x\n", (left << 4) + right);
	return ((left << 4) + right);
}

void	feed_bin(unsigned char *bin, const char *hex)
{
	ssize_t size = 17;
	unsigned char tmp[17];
	char **tab = NULL;

	bzero(tmp, 17);
	while (size)
	{
		tmp[size] = tolower(hex[size]);
		--size;
	}
	tab = ft_split(hex, ':');
	while (*tab)
		*bin++ = hextobyte(*tab++);
//	while (size <= 17)
//		tmp[size] = tmp[size++] - 87;
}

void	print_mac(unsigned char *bin)
{
	printf("MAC address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", bin[0], bin[1], bin[2], bin[3], bin[4], bin[5]);
}


int main(int ac, char **av)
{
	if (ac == 2)
	{
		if (is_valid_mac(av[1]) < 0)
		{
			printf("Invalid MAC address");
			return (-1);
		}
		unsigned char bin[12] = {0};
		feed_bin(bin, av[1]);
		print_mac(bin);
	}
	return (0);
}
