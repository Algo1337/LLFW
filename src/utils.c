#include "init.h"

HEAP_USED RETURN_HEAP
public string ip_to_str(unsigned int ip)
{
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

public fn print_ip(unsigned int ip)
{
    unsigned int h = _ntohl(ip);
    unsigned char *b = (unsigned char *)&h;

    printi(b[0]); print(".");
    printi(b[1]); print(".");
    printi(b[2]); print(".");
    printi(b[3]);
}

string create_drop_cmd(string ip) {
    // string cmd = init_str();
}