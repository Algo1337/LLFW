#include "init.h"

public req_t init_request(protocol_t protocol, string sip, i32 sport, string dip, i32 dport)
{
    req_t r = allocate(0, sizeof(request));

    r->protocol = protocol;

    r->src_ip = sip;
    r->src_port = sport;

    r->dest_ip = dip;
    r->dest_port = dport;

    return r;
}

public fn req_Destruct(req_t r)
{
    if(!r)
        return;
        
    if(r->src_ip)
        _pfree(r->src_ip);

    if(r->dest_ip)
        _pfree(r->dest_ip);

    if(r->buffer)
        _pfree(r->buffer);

    _pfree(r);
}