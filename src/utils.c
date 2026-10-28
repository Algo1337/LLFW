#include "init.h"

public string read_file(string filename)
{
	if(!filename)
		return NULL;

	fd_t file = open_file(filename, 0, 0);
	if(!file)
		return NULL;

	int sz = file_content_size(file);
	if(sz == 0)
		return NULL;

	string buffer = allocate(0, sz + 1);
	int bytes = file_read(file, buffer, sz);
	
	if(bytes > 0)
		return buffer;

	_pfree(buffer);
	return NULL;
}

public struct sleep_t get_time_now()
{
    struct sleep_t dt = {0, 0};
    __syscall__(1, (long)&dt, -1, -1, -1, -1, _SYS_CLOCK_GETTIME);

    return dt;
}

HEAP_USED RETURN_HEAP
public string ip_to_str(unsigned int ip)
{
    unsigned int h = _ntohl(ip);
    unsigned char *b = (unsigned char *)&h;
    
    string n = allocate(0, 20);
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