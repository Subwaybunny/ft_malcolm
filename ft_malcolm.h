/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_malcolm.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:20:48 by jragot            #+#    #+#             */
/*   Updated: 2021/09/15 21:37:46 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef _FT_MALCOLM_H_
# define _FT_MALCOLM_H_
# include <stdio.h>
# include <unistd.h>
# include <string.h>
# include <ctype.h>
# include <stdlib.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <net/ethernet.h>
# include <net/if_arp.h>
# include <ifaddrs.h>
# include "ft_split.c"
# include "count_tab.c"
# include "ft_putlen.c"

struct arp_ip
{
    unsigned short int ar_hrd;          /* Format of hardware address.  */
    unsigned short int ar_pro;          /* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    unsigned short int ar_op;           /* ARP opcode (command).  */
    unsigned char ar_sha[ETH_ALEN];     /* Sender hardware address.  */
    unsigned char ar_sip[4];            /* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN];     /* Target hardware address.  */
    unsigned char ar_tip[4];            /* Target IP address.  */
};

size_t          count_tab(char **tab);
int             isbase16(char c);
int             is_valid_mac(const char *addr);
int             is_valid_ipv4(const char *addr);
void            ft_putlen(unsigned char* str, ssize_t len);
void	        feed_bin(unsigned char *bin, const char *hex);
void	        print_mac(unsigned char *bin);
void	        exit_error(const char *message);
void	        requirements(int ac, char **av);
void            process_ethernet(unsigned char *buffer, ssize_t buflen);
void            process_arp(unsigned char *buffer, ssize_t buflen);
void	        print_buffer(unsigned char *buffer, ssize_t buflen);
void	        print_raw_data(unsigned char *buffer);
char	        hextobyte(const char *hex);
unsigned char	*craft_arp(const char *sip, unsigned char *raw_arp);
struct hostent  *gethost(const char *name);
struct ifaddrs  *getinterface(struct ifaddrs *iflist,const char *name);
#endif