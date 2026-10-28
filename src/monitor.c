#include "init.h"

public fn set_default_display(firewall_t fw)
{
    string layout = read_file("assets/layout.fw");
    int h = count_char(layout, '\n') + 1, w = (find_char(layout, '\n') / 3);
    _printf("Size: %d:%d\n", (ptr)&h, (ptr)&w);
    _sleep(2);
    _printf("\033[8;%d;%dt", (ptr)&h, (ptr)&w);
    print(layout);
}

public fn monitor()
{
    register firewall_t fw asm("r13");
    set_default_display(fw);
    init_mem();
    struct sleep_t last = get_time_now();

    fw->capture_running = 1;
    while(fw->capture_running != 0)
    {
        struct sleep_t time = get_time_now();
        if(time.sec - last.sec >= 1)
        {
            last.sec = time.sec;
            print("\x1b[3;70f         ");
            _printf("\x1b[3;70f%d", (ptr)&fw->pps);
        }
    }

    fw->capture_running = 0;
    uninit_mem();
}