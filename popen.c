#include <fsl.h>

int entry()
{

    popen_t p;
    memzero(&p, sizeof(popen_t));

    char *args[4] = {
        "/usr/curl",
        "-s",
        "https://api.ipify.org",
        NULL
    };

    popen(&p, args[0], args, 0);

    char buf[1024];

    long n = __syscall__(
        p.fd,
        (long)buf,
        sizeof(buf),
        -1, -1, -1,
        _SYS_READ
    );

pclose(&p);    
}