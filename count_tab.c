size_t count_tab(char **tab)
{
	size_t size = 0;

	while (*tab++)
		++size;
	return (size);
}
