#include "init.h"

public fn capture(/* firewall_t fw */)
{
    register firewall_t fw asm("r13");
    init_mem();
    struct sleep_t last = get_time_now();
    fw->capture_running = 1;

    string data = _EXTERNAL_;
    while(fw->capture_running != 0)
    {
        struct sleep_t time = get_time_now();
        if(time.sec - last.sec >= 1)
        {
            last.sec = time.sec;
            // print("             \r");
            // _printf("PPS -> %d\r", (ptr)&fw->pps);
            fw->pps = 0;
        }

        int bytes = __syscall__(fw->socket->fd, (long)data, fw->socket->buff_len, -1, -1, -1, _SYS_READ);
        if(bytes <= 0)
            continue;

        fw->pps += bytes;
        fw->ticks++;

        req_t t;
        if((t = parse_request(fw, data, bytes)) <= 0) {
            // println("Failed to parse a request!\n");
            continue;
        }
        
        req_Destruct(t);
    }

    fw->capture_running = 0;
    uninit_mem();
}

//
HEAP_USED
//
public req_t parse_request(firewall_t fw, unsigned char *buf, len_t len)
{
    if (len < 14) return NULL;

    unsigned short proto = (buf[12] << 8) | buf[13];

    if (proto != 0x0800) return NULL;
    if (len < 14 + 20) return NULL;

    unsigned char *ip = buf + 14;

    u8 ihl = ip[0] & 0x0F;
    int ip_header_len = ihl * 4;

    u32 saddr = (ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8)  | (ip[15]);
    u32 daddr = (ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8)  | (ip[19]);


    /* TODO; Move protection into a new function */
    request c;
    c.protocol = 0;
    /*
        for incoming request, the format is:
            - Inbound (sip): Client IP
            - Outbount (dip): Device IP
    */
    c.src_ip = ip_to_str((ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8)  | (ip[15]));
    c.dest_ip = ip_to_str((ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8)  | (ip[19]));

    if(!c.src_ip || !c.dest_ip)
        return NULL;

    c.src_ip[17] = '\0';
    c.dest_ip[17] = '\0';

    unsigned char protocol = ip[9];
    if(protocol == 1) {
        c.protocol = ICMP;
        unsigned char *icmp = buf + 14 + ip_header_len;

        /* used ; dunno yet */
        unsigned char type = icmp[0];
        unsigned char code = icmp[1];

    } else if(protocol == 6) {
        c.protocol = TCP;
        unsigned char *tcp = buf + 14 + ip_header_len;

        c.src_port = (tcp[0] << 8) | tcp[1];
        c.dest_port = (tcp[2] << 8) | tcp[3];
        c.flags = tcp[13];

        /* unused */
        int syn = (c.flags & 0x02) != 0;
        int ack = (c.flags & 0x10) != 0;
        int fin = (c.flags & 0x01) != 0;
    }
    else if(protocol == 17) {
        c.protocol = UDP;
        unsigned char *udp = buf + 14 + ip_header_len;

        c.src_port = (udp[0] << 8) | udp[1];
        c.dest_port = (udp[2] << 8) | udp[3];
    }

    if(len > 0) {
        c.length = len;
        c.buffer = allocate(0, len + 1);
        mem_cpy(c.buffer, buf, len);
    }

    return to_heap(&c, sizeof(request));
}

public bool check_request(firewall_t fw, req_t c, string buff)
{
    u32 *ip = (u32 *)buff + 14;

    if(!c->src_ip || !c->dest_ip) {
        return 0;
    }

    /* Skip whitlisted/protected IPs */
    if (fw->system_ip && !str_cmp(fw->system_ip, c->dest_ip)) {
        println("Request: Incoming (to server)");
    } else if (fw->system_ip && !str_cmp(fw->system_ip, c->src_ip)) {
        println("Request: Outgoing (from server)");
    }

    if(is_ip_whitlisted(fw, c->dest_ip) > -1 || (fw->user_ip && str_cmp(c->dest_ip, fw->user_ip))) {
        return 2;
    }

    if(!fw->capture_running) {
        return -1;
    }

    if(is_ip_blacklisted(fw, c->src_ip) > -1)
    {
        /* ENSURE IP IS NOT ALREADY BLOCKED (fw->blocked) */
        if(array_contains_str(fw->blocked, c->src_ip) > -1)
        {

        }

        _printf("IP Blocked: %s\n", c->dest_ip);
        return 1;
    }

    u32 *payload = ip + IP_HDR_LEN;
    // int payload_sz = c->length - (c->buffer - c->payload);
    
    // Method Checking and Blocking here....
    // specific methods include special formats, sometimes following custom TCP protocol(s)
    // check_dd0s_methods();

    // Validate further data...

    return 0;
}

public fn req_Destruct(req_t r)
{
    if(r->src_ip)
        _pfree(r->src_ip);

    if(r->dest_ip)
        _pfree(r->dest_ip);

    if(r->buffer)
        _pfree(r->buffer);

    _pfree(r);
}