#include "src/init.h"

string args[100 * 8];

public string HELP_LIST = "   Name           Description\r\n"
"______________________________________\r\n"
"   --serv_ip      Provide the server IP to protect\r\n"
"   --myip         You're IP to whitlist\r\n"
"   --debug        Enable debug mode\r\n";

public fn term_cli();

public int entry(int argc, string argv[])
{
    mem_cpy(args, argv, 8 * argc);
    uninit_mem();
    set_heap_sz(526870912);
    init_mem();
    firewall_t fw = init_firewall(NULL, 1);
    toggle_protection(fw);

    int pos = 0;
    // if(array_contains_str((array)args, "--debug"))
    //     toggle_debug_mode();

    if((pos = array_contains_str((array)args, "--serv_ip")) > -1)
        fw->system_ip = str_dup(args[pos + 1]);

    if((pos = array_contains_str((array)args, "--myip")) > -1)
        whitlist_ip(fw, args[pos + 1]);

    _printf("Socket: %d\n", (void *)&fw->socket->fd);

    thread t = create_thread((handler_t)monitor, fw, 0);
    start_thread(t);

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
        }
    }
}