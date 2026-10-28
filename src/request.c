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