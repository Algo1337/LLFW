#pragma once

#include <fsl.h>

// IP: [3]
#define DROP_IP_CMD { "conntrack", "-D", "-s", "[IP]", NULL }

// IP: [4]
#define BLOCK_INPUT_REQ { "iptables", "-A", "INPUT", "-s", "[IP]", "-j", "DROP", NULL }

// IP: [4]
#define BLOCK_OUTPUT_REQ { "iptables", "-A", "OUTPUT", "-s", "[IP]", "-j", "DROP", NULL }

// struct pollfd {
//     int fd;
//     short events;
//     short revents;
// };

struct ip_hdr {
    unsigned char  ver_ihl;      // Version (4 bits) + IHL (4 bits)
    unsigned char  tos;          // Type of Service
    unsigned short tot_len;      // Total Length
    unsigned short id;           // Identification
    unsigned short frag_off;     // Flags (3 bits) + Fragment Offset (13 bits)
    unsigned char  ttl;          // Time To Live
    unsigned char  protocol;     // Protocol (TCP=6, UDP=17, etc.)
    unsigned short check;        // Header checksum
    unsigned int   saddr;        // Source IP
    unsigned int   daddr;        // Destination IP
    // options may follow if IHL > 5
};

#define ETH_HDR_LEN sizeof(struct eth_hdr)
#define IP_HDR_LEN sizeof(struct ip_hdr)
#define TCP_HDR_LEN sizeof(struct tcp_hdr)

#define POLLIN 0x001

typedef struct
{
    string      src_ip;
    int         src_port;
    string      dest_ip;
    int         dest_port;

    string      buffer;
    len_t       length;
} connection;

typedef connection *conn_t;
typedef connection **conn_arr_t;
typedef struct 
{
    /* Raw Socket Info */
    sock_t      socket;

    /* Protection Info */
    string      system_ip;       // System IP (Whitlisted)

    array       whitlisted;
    array       blacklisted;


    /* Monitor Stats */
    int         ticks;
    int         pps;

    /* Monitor Settings / Adjustable Protection Settings */
    int         enable_protection;
    int         auto_reset_ips;
    int         running;
    int         online;
    int         under_attack;

    /* Max Connection Acceptable System-Wide */
    int         cons_acceptable;

    /* Default; 2 Connections for IP */
    int         max_cons_per_ip;

    /*
        Depending on the apps hosted on the system, This is to be adjusted to user(s)
        and//or how app(s) works.

        Example: 
            for Simple API Request(s), the max connnections per port count can stay low since it doesnt hold connections for to long.
            Stay-alive apps will need this adjusted
    */
    int         max_cons_per_port;
    
    /*
        This array stores all suspecious IPs currently temporarily blocked during attack(s)

        IPs are to be released/unblocked if 'auto_reset_ips' is enabled after the
        attack(s) are done and server is no longer under load

        List of suspeciousness:
            - Connection Spams
            - High Packet Count Spams ( Including payloads randomization )
            - Over the count of 'max_cons_per_ip'
    */
    array       blocked;
} firewall;

typedef firewall *firewall_t;

/* init.c */
public firewall_t   init_firewall(string ip, int protection);
public fn           toggle_protection(firewall_t fw);
public bool         whitlist_ip(firewall_t fw, string ip);
public bool         blacklist_ip(firewall_t fw, string ip);
public bool         is_ip_whitlisted(firewall_t fw, string ip);
public bool         is_ip_blacklisted(firewall_t fw, string ip);
public fn           firewall_destruct(firewall_t fw);

/* monitor.c */
public fn           monitor(firewall_t fw);
public bool         parse_request(firewall_t fw, unsigned char *buf, len_t len);
public bool         check_request(firewall_t fw, conn_t c, string buff);

/* utils.c */
HEAP_USED
public string       ip_to_str(unsigned int ip);
public fn           print_ip(unsigned int ip);