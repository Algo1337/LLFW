/*
    Dependencies:
        sudo apt install iptables -y
        sudo apt install conntrack -y
*/
#include <fsl.h>

// IP: [3]
#define DROP_IP_CMD { "conntrack", "-D", "-s", "[IP]", NULL }
string create_drop_cmd(string ip) {
    // string cmd = init_str();
}

// IP: [4]
#define BLOCK_INPUT_REQ { "iptables", "-A", "INPUT", "-s", "[IP]", "-j", "DROP", NULL }

// IP: [4]
#define BLOCK_OUTPUT_REQ { "iptables", "-A", "OUTPUT", "-s", "[IP]", "-j", "DROP", NULL }

struct pollfd {
    int fd;
    short events;
    short revents;
};

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

public bool check_request(firewall_t fw, conn_t c, string buff);

public firewall_t init_firewall(string ip, int protection)
{
    firewall_t fw = allocate(0, sizeof(firewall));
    fw->system_ip = ip ? str_dup(ip) : NULL;
    fw->enable_protection = protection;

    fw->blacklisted = init_array();
    fw->whitlisted = init_array();

    fw->blocked = init_array();

    fw->socket = allocate(0, sizeof(sock_t));
    fw->socket->fd = __syscall__(17, 3, _htons(0x0003), -1, -1, -1, _SYS_SOCKET);
    if(fw->socket->fd < 0)
        fsl_panic("unable to create socket!");

    mem_set(&fw->socket->addr, 0, sizeof(addr_in));
    fw->socket->buff_len = 1024;

    return fw;
}

public fn toggle_protection(firewall_t fw)
{ fw->enable_protection = fw->enable_protection ? 0 : 1; }

public bool whitlist_ip(firewall_t fw, string ip)
{
    if(!fw || !ip)
        return 0;

    fw->whitlisted = array_append(fw->whitlisted, ip);
    return 1;
}

public bool blacklist_ip(firewall_t fw, string ip)
{
    if(!fw || !ip)
        return 0;

    fw->blacklisted = array_append(fw->blacklisted, ip);
    return 1;
}

/* 
    Check if an IP Address is already whitlisted 

    NOTE: IPs here can never be blocked during an attack
*/
public bool is_ip_whitlisted(firewall_t fw, string ip)
{
    if(!fw || !ip)
        return -1;

    for(int i = 0; i < __get_size__(fw->whitlisted); i++)
    {
        if(!((string *)fw->whitlisted)[i])
            break;

        if(str_cmp(((string *)fw->whitlisted)[i], ip))
            return i;
    }

    return -1;
}
/* 
    Check if an IP Address is already blacklisted
*/
public bool is_ip_blacklisted(firewall_t fw, string ip)
{
    if(!fw || !ip)
        return -1;

    for(int i = 0; i < __get_size__(fw->blacklisted); i++)
    {
        if(!((string *)fw->blacklisted)[i])
            break;

        if(str_cmp(((string *)fw->blacklisted)[i], ip))
            return i;
    }

    return -1;
}

public fn firewall_destruct(firewall_t fw)
{
    if(!fw)
        return;

    __syscall__(fw->socket->fd, -1, -1, -1, -1, -1, _SYS_CLOSE);

    pfree(fw->system_ip, 1);

    if(fw->whitlisted)
        pfree_array((array)fw->whitlisted);

    if(fw->blacklisted)
        pfree_array((array)fw->blacklisted);
}

HEAP_USED
public string ip_to_str(unsigned int ip) {
    unsigned int h = _ntohl(ip);
    unsigned char *b = (unsigned char *)&h;
    
    string n = allocate(0, 16);
    str_append_int(n, b[0]);
    str_append(n, ".");
    str_append_int(n, b[1]);
    str_append(n, ".");
    str_append_int(n, b[2]);
    str_append(n, ".");
    str_append_int(n, b[3]);

    return n;
}

public fn print_ip(unsigned int ip) {
    unsigned int h = _ntohl(ip);
    unsigned char *b = (unsigned char *)&h;

    printi(b[0]); print(".");
    printi(b[1]); print(".");
    printi(b[2]); print(".");
    printi(b[3]);
}

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

HEAP_USED
public bool parse(firewall_t fw, unsigned char *buf, len_t len) {
    if (len < 14) return 0;

    unsigned short proto = (buf[12] << 8) | buf[13];

    if (proto != 0x0800) return 0;
    if (len < 14 + 20) return 0;

    unsigned char *ip = buf + 14;

    unsigned char ihl = ip[0] & 0x0F;
    int ip_header_len = ihl * 4;

    unsigned int saddr =
        (ip[12] << 24) | (ip[13] << 16) |
        (ip[14] << 8)  | (ip[15]);

    unsigned int daddr =
        (ip[16] << 24) | (ip[17] << 16) |
        (ip[18] << 8)  | (ip[19]);


    /* TODO; Move protection into a new function */
    conn_t c;
    int v = check_request(fw, c, buf);
    if(v == 2) // Whitlisted
        return 0;

    if(v == 1) // Suspecious Connection
    {
        return 0;
    }

    _printf("\x1b[32mNew Request, Byte Size: %d\x1b[39m\n", (void *)&len);
    print("=== IP ===\nSrc: "), print_ip(saddr);
    print("\nDst: "), print_ip(daddr);
    print("\n");

    unsigned char protocol = ip[9];
    if(protocol == 1) {
        unsigned char *icmp = buf + 14 + ip_header_len;

        unsigned char type = icmp[0];
        unsigned char code = icmp[1];

        print("\x1b[33m=== ICMP ===\x1b[39m\n");

        print("Type: "), printi(type);
        print(" | Code: "), printi(code), println(NULL);

        print("\n");
    } else if(protocol == 6) {
        unsigned char *tcp = buf + 14 + ip_header_len;

        unsigned short sport = (tcp[0] << 8) | tcp[1];
        unsigned short dport = (tcp[2] << 8) | tcp[3];
        unsigned char flags = tcp[13];

        print("\x1b[31m=== TCP ===\x1b[39m\nSrc Port: "), printi(sport), print(" | Dst Port: "), printi(dport), println(NULL);

        int syn = (flags & 0x02) != 0;
        int ack = (flags & 0x10) != 0;
        int fin = (flags & 0x01) != 0;
        _printf("Flags: SYN = %d | ACK = %d | FIN = %d\n", (void *)&syn, (void *)&ack, (void *)&fin);
    }
    else if(protocol == 17) {
        unsigned char *udp = buf + 14 + ip_header_len;

        unsigned short sport = (udp[0] << 8) | udp[1];
        unsigned short dport = (udp[2] << 8) | udp[3];

        println("\x1b[32m=== UDP ===\x1b[39m\n");
        print("Src Port: "), printi(sport), print(" | Dst Port: "), printi(dport), println(NULL);
    }

    // char byte[4];
    // println("\x1b[32mRequest Info\x1b[39m");
    // for (size_t i = 0; i < len; i++) {
    //     byte_to_hex(buf[i], byte); 
    //     _printf("%s ", byte);
    // }
    // println("\n");

    return 1;
}

public bool check_request(firewall_t fw, conn_t c, string buff)
{
    u32 *ip = (u32 *)buff + 14;

    /*
        for incoming request, the format is:
            - Inbound (sip): Client IP
            - Outbount (dip): Device IP
    */
    string sip = ip_to_str((ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8)  | (ip[15]));
    string dip = ip_to_str((ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8)  | (ip[19]));

    if(!sip || !dip)
        return 0;

    /* Skip whitlisted/protected IPs */
    if (fw->system_ip && !str_cmp(fw->system_ip, dip)) {
        println("Request: Incoming (to server)");
    } else if (fw->system_ip && !str_cmp(fw->system_ip, sip)) {
        println("Request: Outgoing (from server)");
    }

    if(is_ip_whitlisted(fw, dip) > -1)
        return 2;

    if(!fw->enable_protection)
        return -1;

    if(is_ip_blacklisted(fw, sip) > -1)
    {
        /* ENSURE IP IS NOT ALREADY BLOCKED (fw->blocked) */
        if(array_contains_str(fw->blocked, sip) > -1)
        {
            /*
                - BLOCK IP

                DROP IP CONNECTIONS; conntrack -D -s 1.2.3.4
                BLOCK FUTURE IP REQ; 
                    iptables -A INPUT -s 1.2.3.4 -j DROP
                    iptables -A OUTPUT -d 1.2.3.4 -j DROP
            */
        }

        _printf("IP Blocked: %s\n", dip)
        return 1;
    }

    

    // More protction checks

    u32 *payload = ip + IP_HDR_LEN;

    pfree(sip, 1);
    pfree(dip, 1);

    return 0;
}

public fn monitor(firewall_t fw)
{
    fw->running = 1;

    string data = _EXTERNAL_;
    
    while(fw->running != 0)
    {
        int sz = 1024;
        int bytes = __syscall__(fw->socket->fd, (long)data, 1023, -1, -1, -1, _SYS_READ);

        if(bytes > 0) {
            parse(fw, data, bytes);
        }

        fw->ticks++;
    }
}

string args[50 * 8];

public int entry(int argc, string argv[])
{
    mem_cpy(args, argv, argc * 8);
    uninit_mem();
    set_heap_sz(526870912);
    init_mem();
    firewall_t fw = init_firewall(NULL, 1);
    toggle_protection(fw);

    int pos = 0;
    if(pos = array_contains_str((array)args, "--serv_ip"))
        fw->system_ip = str_dup(args[pos + 1]);

    if(pos = array_contains_str((array)args, "--serv_ip"))
        whitlist_ip(fw, args[pos + 1]);

    _printf("Socket: %d\n", (void *)&fw->socket->fd);

    monitor(fw);
    return 0;
}
