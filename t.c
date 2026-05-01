#include <fsl.h>

extern int __ARGC__;
extern string __ARGV__[80];
int entry(int argc, string argv[])
{
    int pos = array_contains_str((array)__ARGV__, "--debug");
    if(pos > -1)
        println("Debug flag found!");
    
    printi(pos), println(NULL);
    pos = array_contains_str((array)__ARGV__, "--serv_ip");
    if(pos > -1)
        println("ServerIP flag found!");

    printi(pos), println(NULL);
    pos = array_contains_str((array)__ARGV__, "--myip");
    if(pos > -1)
        println("MyIP flag found!");

    printi(pos), println(NULL);
    return 0;
}