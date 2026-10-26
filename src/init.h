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

typedef enum
{
    ICMP,
    UDP,
    TCP
} protocol_t;

typedef struct
{
    protocol_t  protocol;
    string      src_ip;
    int         src_port;
    string      dest_ip;
    int         dest_port;
    int         flags;

    string      buffer;
    len_t       length;
} request;

typedef request *req_t;
typedef request **req_arr_t;

typedef struct
{
    string  name;
    int     enable_protection;
    int     auto_reset_ips;

    array   whitelisted;        // Whitelisted Cons
    array   blacklisted;        // Blacklisted Cons

    array   rules;
    array   services;
    
    i32     max_pps;            // Max PPS
    i32     max_cons;           // Global Max Cons
    i32     max_cons_per_ip;    // Max Cons Per IP
    i32     max_cons_per_port;  // Max Cons Per Port
} _config;

typedef _config cfg_t;


typedef struct 
{
    /* Raw Socket Info */
    sock_t      socket;

    /* Protection Info */
    string      system_ip;       // System IP (Whitlisted)
    string      user_ip;

    _config     Config;
    array       blocked;        // Connection blocked during runtime


    /* Monitor Stats */
    int         max_pps;
    int         ticks;
    int         pps;

    /* Monitor Settings / Adjustable Protection Settings */
    int         capture_running;
    int         monitor_running;
    int         online;
    int         under_attack;
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

/* capture.c */
public fn           capture(/* firewall_t fw */);
public req_t        parse_request(firewall_t fw, unsigned char *buf, len_t len);
public bool         check_request(firewall_t fw, req_t c, string buff);
public fn           req_Destruct(req_t r);

/* monitor */
public fn           monitor();

/* utils.c */
public string read_file(string filename);
public struct sleep_t      get_time_now();
HEAP_USED
public string       ip_to_str(unsigned int ip);
public fn           print_ip(unsigned int ip);