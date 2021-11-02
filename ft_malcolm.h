/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_malcolm.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jragot <jragot@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/15 21:20:48 by jragot            #+#    #+#             */
/*   Updated: 2021/11/02 01:39:12 by jragot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef _FT_MALCOLM_H_
# define _FT_MALCOLM_H_
# include <stdio.h>
# include <unistd.h>
# include <string.h>
# include <ctype.h>
# include <stdlib.h>
# include <signal.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <net/ethernet.h>
# include <net/if_arp.h>
# include <linux/if_packet.h>
# include <ifaddrs.h>
# define ETH0 2
# define WLAN0 3

struct arp_ip
{
    unsigned char ar_hrd[2];          /* Format of hardware address.  */
    unsigned char ar_pro[2];          /* Format of protocol address.  */
    unsigned char ar_hln;             /* Length of hardware address.  */
    unsigned char ar_pln;             /* Length of protocol address.  */
    unsigned char ar_op[2];           /* ARP opcode (command).  */
    unsigned char ar_sha[6];          /* Sender hardware address.  */
    unsigned char ar_sip[4];          /* Sender IP address.  */
    unsigned char ar_tha[6];          /* Target hardware address.  */
    unsigned char ar_tip[4];          /* Target IP address.  */
};

struct addr_set
{
    unsigned char tmac[6];           /* Target MAC address */
    unsigned char smac[6];           /* Source MAC address */
    in_addr_t tip;                   /* Target IP address */
    in_addr_t sip;                   /* Source IP address */
};

size_t          count_tab(char **tab);                      // MOVE TO LIBfT
int             isbase16(char c);                           // MOVE TO LIBFT
int             is_valid_mac(const char *addr);
int             is_valid_ipv4(const char *addr);
void            sig_handler(int sig);
void            ft_putlen(unsigned char* str, ssize_t len); // MOVE TO LIBFT
void	        feed_bin(unsigned char *bin, const char *hex);
void	        print_mac(unsigned char *bin);
void	        exit_error(const char *message);            // MOVE TO LIBFT
void	        requirements(int ac, char **av);
void            process_ethernet(unsigned char *buffer, ssize_t buflen);
void            process_arp(unsigned char *buffer);
void	        arp_reply(struct arp_ip *request);
void	        print_buffer(unsigned char *buffer, ssize_t buflen);
void	        print_raw_data(unsigned char *buffer);
void            ft_putlen(unsigned char* str, ssize_t len);
char	        hextobyte(const char *hex);
unsigned char	*craft_arp(unsigned char *output);
struct hostent  *gethost(const char *name);
struct ifaddrs  *getinterface(struct ifaddrs *iflist,const char *name);
/* SUPPORT FOR FT_SPLIT */
char            **ft_split(char const *s, char c);
#endif