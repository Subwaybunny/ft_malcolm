/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:55:24 by jragot            #+#    #+#             */
/*   Updated: 2021/09/15 22:56:29 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef _LIBFT_H_
# define _LIBFT_H_
# include <unistd.h>
# include <stdlib.h>

int     isbase16(char c);
size_t  count_tab(char **tab);
void    ft_putlen(unsigned char* str, ssize_t len);
void    exit_error(const char *message);
#endif
