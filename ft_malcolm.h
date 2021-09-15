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
