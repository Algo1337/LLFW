#include "src/init.h"

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
