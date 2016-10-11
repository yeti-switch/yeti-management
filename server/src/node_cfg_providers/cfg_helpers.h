#pragma once

#include <confuse.h>

#include <string>

bool inline add2hash(cfg_t *c,std::string key,std::string cfg_key,
						 cfg_provider::cfg_keys &out)
{
	cfg_opt_t *opt = cfg_getopt(c,cfg_key.c_str());
	if(!opt || !opt->nvalues) return false;

	switch(opt->type){
	case CFGT_INT:
		if(opt->flags&CFGF_LIST)
			err("list of integers is unsupported. assign first value");
		out[key] = cfg_getint(c,cfg_key.c_str());
		break;
	case CFGT_STR:
		if(opt->flags&CFGF_LIST){
			std::string s;
			for(int i = 0; i < cfg_size(c, cfg_key.c_str()); i++){
				if(!s.empty()) s.append(",");
				s.append(cfg_getnstr(c, cfg_key.c_str(), i));
			}
			out[key] = s;
		} else {
			out[key] = cfg_getstr(c,cfg_key.c_str());
		}
		break;
	case CFGT_BOOL:
		if(opt->flags&CFGF_LIST)
			err("list of booleans is unsupported. assign first value");
		out[key] = cfg_getbool(c,cfg_key.c_str());
		break;
	default:
		err("uknown option type: %d for key: '%s'",
			 opt->type,cfg_key.c_str());
	}
	return true;
}

inline void apply_db_cfg(cfg_t *c,std::string prefix,
						   cfg_provider::cfg_keys &out)
{
	add2hash(c,prefix+"host","host",out);
	add2hash(c,prefix+"port","port",out);
	add2hash(c,prefix+"name","name",out);
	add2hash(c,prefix+"user","user",out);
	add2hash(c,prefix+"pass","pass",out);
}

inline void apply_redis_pool_cfg(cfg_t *c,std::string prefix,
						   cfg_provider::cfg_keys &out)
{
	add2hash(c,prefix+"socket","socket",out);
	add2hash(c,prefix+"host","host",out);
	add2hash(c,prefix+"port","port",out);
	add2hash(c,prefix+"size","size",out);
	add2hash(c,prefix+"timeout","timeout",out);
}
