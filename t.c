#include "src/init.h"

public i8 entry(int argc, string argv[])
{
	uninit_mem();
	set_heap_sz(_HEAP_PAGE_ * 5);
	init_mem();
	string data = read_file("assets/config.cfg");

	i32 line_count = 0;
	sArr lines = split_string(data, '\n', &line_count);

	if(!lines)
		fsl_panic("Unable to split");

		
	_config *cfg = allocate(0, sizeof(_config));

	cfg->whitelist = init_array();
	cfg->blacklisted = init_array();
	cfg->rules = init_array();
	cfg->services = init_array();

	char block[255];
	for(int i = 0; i < line_count; i++)
	{
		if(!lines)
			break;

		if(is_empty(lines[i]) || lines[i][0] == '\0' || lines[i][0] == '\r')
			continue;

		if(str_startswith(lines[i], "{") || str_startswith(lines[i], "}"))
			continue;

		if(str_startswith(lines[i], "//"))
			continue;

		if(str_startswith(lines[i], "[@"))
		{
			memzero(block, 255);
			int len = _str_len(lines[i]);
			trim_char_idx(lines[i], len - 2);
			trim_char_idx(lines[i], 0);
			trim_char_idx(lines[i], 0);
			
			mem_cpy(block, lines[i], len - 4);
			_printf("Block -> %d:'%s'\n", (ptr)&len, block);
			continue;
		}

		str_strip(lines[i]);
		if(str_cmp(block, "SETTINGS")) {
			int pos = 0;
			if((pos = find_char(lines[i], ':') == -1)) continue;
			int _argc = 0;
			sArr _args = split_string(lines[i], ':', &_argc);
			if(!_args)
				continue;
			
			if(str_startswith(lines[i], "protection: ")) {
				replace_char(lines[i], '\r', '\0');
				replace_char(lines[i], '\n', '\0');

				cfg->enable_protection = str_to_int(_args[1] + 1);
			}
	
			if(str_startswith(lines[i], "max_pps: ")) {
				replace_char(lines[i], '\r', '\0');
				replace_char(lines[i], '\n', '\0');
				cfg->max_pps = str_to_int(_args[1] + 1);
			}
		
			if(str_startswith(lines[i], "max_connections: ")) {
				replace_char(lines[i], '\r', '\0');
				replace_char(lines[i], '\n', '\0');
				cfg->max_cons = str_to_int(_args[1] + 1);
			}
			
			if(str_startswith(lines[i], "max_con_per_ip: ")) {
				replace_char(lines[i], '\r', '\0');
				replace_char(lines[i], '\n', '\0');
				cfg->max_cons_per_ip = str_to_int(_args[1] + 1);
			}
			
			if(str_startswith(lines[i], "max_con_per_port: ")) {
				replace_char(lines[i], '\r', '\0');
				replace_char(lines[i], '\n', '\0');
				cfg->max_cons_per_port = str_to_int(_args[1] + 1);
			}
				
			if(str_startswith(lines[i], "discord_webhook_api: ")) {
				string url = lines[i] + pos;
				cfg->discord_url = str_dup(url);
			}

			_printf("Key: %s | Value: %s\n", _args[0], _args[1]);
		} else if(str_cmp(block, "RULES")) {
			_printf("Rule: %s\n", lines[i]);
			cfg->rules = array_append(cfg->rules, lines[i]);
		} else if(str_cmp(block, "PROTECTED_IPS")) {
			if(is_empty(lines[i]))
				continue;

			if(!validate_ip(lines[i]))
				fsl_panic("Invalid IP");

			_printf("IP: '%s'\n", lines[i]);
			cfg->whitelisted = array_append(cfg->whitelisted, lines[i]);
		} else if(str_cmp(block, "SERVICES")) {
			_printf("SERVICE: %s\n", lines[i]);
			cfg->services = array_append(cfg->services, lines[i]);
		}

	}

	pfree_array((array)lines);

	_printf("%d %d %d %d %d\n", (ptr)&cfg->enable_protection, (ptr)&cfg->max_pps, (ptr)&cfg->max_cons, (ptr)&cfg->max_cons_per_ip, (ptr)&cfg->max_cons_per_port);
	return 0;
}
