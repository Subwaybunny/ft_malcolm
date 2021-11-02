#include "ft_malcolm.h"

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
	printf("feed_bin called\n");
	size_t size = 17;
	unsigned char tmp[17];
	char **tab = NULL;

	bzero(tmp, 17);		// LIBC
	while (size)
	{
		printf("size: %d\n", size);
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
