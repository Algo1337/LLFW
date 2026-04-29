#include "init.h"

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