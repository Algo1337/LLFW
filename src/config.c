#include "init.h"

public cfg_t init_config(string dir)
{		
	_config *cfg = allocate(0, sizeof(_config));

	cfg->whitelisted = init_array();
	cfg->blacklisted = init_array();
	cfg->rules = init_array();
	cfg->services = init_array();
    cfg->dir = allocate(0, 100);
    mem_cpy(cfg->dir, dir, _str_len(dir));

    if(!retrive_theme(cfg))
        fsl_warning("Enable to get theme!");
        
	return cfg;
}

public bool retrive_theme(cfg_t c)
{
    if(!c || !c->dir)
        return false;

    str_append(c->dir, "/config.cfg");
    string data 	= read_file(c->dir);
	i32 line_count 	= 0;
	sArr lines 		= split_string(data, '\n', &line_count);

	if(!lines)
		fsl_panic("Unable to split");

	return parse_settings(c, lines, line_count);
}

public bool parse_settings(cfg_t cfg, sArr lines, int line_count)
{
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
    return 1;
}

public fn cfg_Destruct(cfg_t c)
{
    if(!c)
        return;
    
    if(c->name)
        _pfree(c->name);

    if(c->dir)
        _pfree(c->dir);

    if(c->whitelisted)
        _pfree(c->whitelisted);

    if(c->blacklisted)
        _pfree(c->blacklisted);

    if(c->rules)
        _pfree(c->rules);

    if(c->services)
        _pfree(c->services);

    if(c->discord_url)
        _pfree(c->discord_url);

    _pfree(c);
}