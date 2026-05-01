#include "src/init.h"

public string HELP_LIST = "   Name           Description\r\n"
"______________________________________\r\n"
"   --serv_ip      Provide the server IP to protect\r\n"
"   --myip         You're IP to whitlist\r\n"
"   --debug        Enable debug mode\r\n";

thread cli_thr;

public fn term_cli();

public int entry(int argc, string argv[])
{
    char args[argc][1024];
    for(int i = 0; i < argc; i++)
    {
        int sz = __get_size__(argv[i]);
        mem_cpy(args[i], argv[i], sz);
        args[i][sz] = '\0';
    }

    uninit_mem();
    set_heap_sz(526870912);
    init_mem();
    firewall_t fw = init_firewall(NULL, 1);
    toggle_protection(fw);

    int pos = 0;

    printi(argc), println(NULL);
    for(int i = 0; i < argc; i++)
    {
        println(args[i]);
        if(str_cmp(args[i], "--debug"))
            toggle_debug_mode();

        if(str_cmp(args[i], "--serv_ip"))
            fw->system_ip = str_dup(args[i + 1]);

        if(str_cmp(args[i], "--myip"))
            whitlist_ip(fw, args[pos + 1]);
    }

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