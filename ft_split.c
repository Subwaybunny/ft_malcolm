/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:08:50 by jragot            #+#    #+#             */
/*   Updated: 2021/09/15 21:19:32 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_malcolm.h"
 
static int	strlen_split_i(char const *s, char c)
{
	int	i;
	int size;
 
	i = 0;
	size = 0;
	while (s[i] && s[i] == c)
		++i;
	while (s[i])
	{
		while (s[i] && s[i] == c)
			++i;
		if (s[i] == '\0')
			return (size);
		while (s[i] && s[i] != c)
			++i;
		++size;
	}
	return (size);
}
 
static int	strlen_split_j(char const *s, char c, int i)
{
	int size;
 
	size = 0;
	while (s[i] && s[i++] != c)
		++size;
	return (size);
}
 
static void	fill_tab(char const *s, char *tab, int k, char c)
{
	int j;
 
	j = 0;
	while (s[k] && s[k] != c)
	{
		tab[j] = s[k];
		++j;
		++k;
	}
	tab[j] = '\0';
}
 
char		**ft_split(char const *s, char c)
{
	char	**tab;
	int		len_i;
	int		len_j;
	int		i;
	int		k;
 
	i = 0;
	k = 0;
	if (!s)
		return (NULL);
	len_i = strlen_split_i(s, c);
	if (!(tab = malloc(sizeof(char *) * (len_i + 1))))
		return (NULL);
	while (i < len_i)
	{
		while (s[k] && s[k] == c)
			++k;
		len_j = strlen_split_j(s, c, k);
		if (!(tab[i] = malloc(sizeof(char*) * (len_j + 1))))
			return (NULL);
		fill_tab(s, tab[i++], k, c);
		k += len_j;
	}
	tab[i] = NULL;
	return (tab);
}
