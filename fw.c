#include "src/init.h"

public string BANNER = "╔═╗╦ ╦╔╗ ╔═╗╦═╗  ╔═╗╦ ╦╦╔═╗╦  ╔╦╗\r\n"
"║  ╚╦╝╠╩╗║╣ ╠╦╝  ╚═╗╠═╣║║╣ ║   ║║\r\n"
"╚═╝ ╩ ╚═╝╚═╝╩╚═  ╚═╝╩ ╩╩╚═╝╩═╝═╩╝\r\n";

public string HELP_LIST = "CyberShield | Version: v8.2 | By: @Algo1337\r\n"
"   Flag           Description\r\n"
"______________________________________\r\n"
"   --serv_ip      Provide the server IP to protect\r\n"
"   --myip         Your IP to whitlist\r\n"
"   --debug        Enable debug mode\r\n";

// Fn Decl
public fn term_cli();

// Globals
thread cli_thr;
extern int __ARGC__;
extern string __ARGV__[80];


char SYSTEM_IP[255];
char USER_IP[255];
int PPS = 0;
public int entry(int argc, string argv[])
{
    for(int i = 0; i < __ARGC__; i++)
    {
        if(str_cmp(__ARGV__[i], "--help"))
            print(BANNER), print(HELP_LIST), __exit(0);

        if(str_cmp(__ARGV__[i], "--debug"))
            toggle_debug_mode();
        
        if(str_cmp(__ARGV__[i], "--serv_ip"))
            mem_cpy(SYSTEM_IP, __ARGV__[i + 1], _str_len(__ARGV__[i + 1]));

        if(str_cmp(__ARGV__[i], "--myip"))
            mem_cpy(USER_IP, __ARGV__[i + 1], _str_len(__ARGV__[i + 1]));

        if(str_cmp(__ARGV__[i], "--pps"))
            PPS = str_to_int(__ARGV__[i + 1]);
    }

    uninit_mem();
    set_heap_sz(526870912);
    init_mem();
    firewall_t fw = init_firewall(NULL, 1);
    toggle_protection(fw);

    fw->system_ip = SYSTEM_IP;
    fw->user_ip = str_dup(USER_IP);
    fw->max_pps = PPS;
    _printf("Socket: %d\n", (void *)&fw->socket->fd);

    monitor(fw);
    // run_thread(monitor, fw);

    // term_cli();
    return 0;
}

public fn term_cli()
{
    char INPUT[1024] = {0};
    while(1)
    {
        print("[LLFW] $ ");
        int bytes = __syscall__(0, (long)INPUT, 1024, -1, -1, -1, _SYS_READ);
        if(bytes <= 0)
            continue;

        if(str_cmp(INPUT, "help")) {
            println(HELP_LIST);
        } else if(str_cmp(INPUT, "geo")) {
            println("Working 2");
        } else if(mem_cmp(INPUT, "q", 1)) {
            __exit(0);
        }
    }
}