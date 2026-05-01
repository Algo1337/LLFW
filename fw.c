#include "src/init.h"

string args[50 * 8];

public string HELP_LIST = "   Name           Description\r\n"
"______________________________________\r\n"
"   --serv_ip      Provide the server IP to protect\r\n"
"   --myip         You're IP to whitlist\r\n"
"   --debug        Enable debug mode\r\n";

public int entry(int argc, string argv[])
{
    mem_cpy(args, argv, argc * 8);
    uninit_mem();
    set_heap_sz(526870912);
    init_mem();
    firewall_t fw = init_firewall(NULL, 1);
    toggle_protection(fw);

    int pos = 0;
    if(pos = array_contains_str((array)args, "--debug"))
        toggle_debug_mode();
        
    if(pos = array_contains_str((array)args, "--serv_ip"))
        fw->system_ip = str_dup(args[pos + 1]);

    if(pos = array_contains_str((array)args, "--myip"))
        whitlist_ip(fw, args[pos + 1]);

    _printf("Socket: %d\n", (void *)&fw->socket->fd);

    monitor(fw);
    return 0;
}
