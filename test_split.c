#include <stdlib.h>
#include <stdio.h>
#include "ft_split.c"

size_t count_tab(char **tab)
{
	size_t size = 0;

	while (*tab++)
		++size;
	return (size);
}

int main(int ac, char **av)
{
	char **tab = NULL;

	if (ac == 2)
	{
		tab = ft_split(av[1], '.');
		printf("tab has %d elements\n", count_tab(tab));
		while (*tab)
			printf("%s\n", *tab++);
	}
	return(0);
}
