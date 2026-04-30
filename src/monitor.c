#include "init.h"


public fn monitor(firewall_t fw)
{
    fw->running = 1;

    string data = _EXTERNAL_;
    while(fw->running != 0)
    {
        int bytes = __syscall__(fw->socket->fd, (long)data, fw->socket->buff_len, -1, -1, -1, _SYS_READ);
        if(bytes <= 0)
            continue;

        parse_request(fw, data, bytes);
        fw->pps += bytes;
        fw->ticks++;
    }
}

//
HEAP_USED
//
public bool parse_request(firewall_t fw, unsigned char *buf, len_t len)
{
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

        }

        _printf("IP Blocked: %s\n", dip)
        return 1;
    }

    u32 *payload = ip + IP_HDR_LEN;
    // int payload_sz = c->length - (c->buffer - c->payload);
    
    // Method Checking and Blocking here....
    // specific methods include special formats, sometimes following custom TCP protocol(s)
    // check_dd0s_methods();

    // Validate further data...

    pfree(sip, 1);
    pfree(dip, 1);

    return 0;
}`