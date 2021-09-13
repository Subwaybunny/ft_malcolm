#include <unistd.h>

void	ft_putlen(unsigned char* str, ssize_t len)
{
	write(1, str, len);
}
