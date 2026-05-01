#include "src/init.h"

public string HELP_LIST = "   Name           Description\r\n"
"______________________________________\r\n"
"   --serv_ip      Provide the server IP to protect\r\n"
"   --myip         You're IP to whitlist\r\n"
"   --debug        Enable debug mode\r\n";

// Fn Decl
public fn term_cli();

// Globals
thread cli_thr;
extern int __ARGC__;
extern string __ARGV__[80];

public int entry(int argc, string argv[])
{
    uninit_mem();
    set_heap_sz(526870912);
    init_mem();
    firewall_t fw = init_firewall(NULL, 1);
    toggle_protection(fw);

    int pos = 0;
    if((pos = array_contains_str((array)__ARGV__, "--debug")) > -1)
        toggle_debug_mode();
    
    if((pos = array_contains_str((array)__ARGV__, "--serv_ip")) > -1)
        fw->system_ip = str_dup(__ARGV__[pos + 1]);

    if((pos = array_contains_str((array)__ARGV__, "--myip")) > -1)
        whitlist_ip(fw, __ARGV__[pos + 1]);

    printi(argc), println(NULL);

    _printf("Socket: %d\n", (void *)&fw->socket->fd);

    cli_thr = create_thread((handler_t)monitor, fw, 0);
    start_thread(cli_thr);

    term_cli();
    return 0;
}

public fn term_cli()
{
    char INPUT[1024] = {0};
    while(1)
    {
        print("> ");
        int bytes = get_input(INPUT, 1023);
        if(bytes <= 0)
            continue;

        if(str_cmp(INPUT, "help")) {
            println("working");
        } else if(str_cmp(INPUT, "geo")) {
            println("Working 2");
        } else if(mem_cmp(INPUT, "q", 1)) {
            thread_kill(&cli_thr);
            __exit(0);
        }
    }
}