#include "src/init.h"

public cfg_t init_config()
{		
	_config *cfg = allocate(0, sizeof(_config));

	cfg->whitelisted = init_array();
	cfg->blacklisted = init_array();
	cfg->rules = init_array();
	cfg->services = init_array();

	return cfg;
}

char filename[100];
public i8 entry(int argc, string argv[])
{
	if(argc < 2)
	{
		_printf("Invalid arguments provided!\nUsage: %s <config_file>", argv[0]);
		return 1;
	}

	_printf("\x1b[32m[ + ]\x1b[39m Retrieving Config Settings: %s.....!\r\n", argv[1]);
	mem_cpy(filename, argv[1], 30);

	uninit_mem();
	set_heap_sz(_HEAP_PAGE_ * 5);
	init_mem();

	string data 	= read_file(filename);
	i32 line_count 	= 0;
	sArr lines 		= split_string(data, '\n', &line_count);

	if(!lines)
		fsl_panic("Unable to split");

		
	cfg_t cfg = init_config();

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
			_printf("\x1b[32m[ + ]\x1b[39m Parsing: %s.....!\n", block);
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

		} else if(str_cmp(block, "RULES")) {
			replace_char(lines[i], '\r', '\0');
			replace_char(lines[i], '\n', '\0');
			
			cfg->rules = array_append(cfg->rules, lines[i]);
		} else if(str_cmp(block, "PROTECTED_IPS")) {
			if(is_empty(lines[i]))
				continue;

			replace_char(lines[i], '\r', '\0');
			replace_char(lines[i], '\n', '\0');
			if(!validate_ip(lines[i]))
				fsl_panic("Invalid IP");

			cfg->whitelisted = array_append(cfg->whitelisted, lines[i]);
		} else if(str_cmp(block, "SERVICES")) {
			replace_char(lines[i], '\r', '\0');
			replace_char(lines[i], '\n', '\0');

			int _argc = 0;
			sArr _args = split_string(lines[i], ';', &_argc);
			_service s; 
			s.name = _args[1];
			s.port = str_to_int(_args[0] + 1);
			s.protocol = 0;
			s.restart_cmd = _args[3];
			s.max_cons = str_to_int(_args[4]);
			s.max_pps = str_to_int(_args[5]);
			s.filter = str_to_int(_args[6]);
			s.drop = str_to_int(_args[7]);

			srvc n = to_heap(&s, sizeof(_service));
			cfg->services = array_append(cfg->services, n);
		}

	}

	pfree_array((array)lines);
	println("\x1b[32m[ + ]\x1b[39m Displaying Settings Info: ");
	_printf("Protection Enabled: %d\nMax PPS: %d\nMax Cons: %d\nMax Con Per IP: %d\nMax Con Per Port: %d\n", 
		(ptr)&cfg->enable_protection,
		(ptr)&cfg->max_pps,
		(ptr)&cfg->max_cons,
		(ptr)&cfg->max_cons_per_ip,
		(ptr)&cfg->max_cons_per_port
	);

	/* Services to protect */
	println("\x1b[32m[ + ]\x1b[39m Protected Services");
	for(int i = 0; cfg->services[i] != NULL; i++)
	{
		srvc t = (srvc)cfg->services[i];
		_printf("Service: %s | Max PPS: %d\n", t->name, (ptr)&t->max_pps);
	}
	return 0;
}
