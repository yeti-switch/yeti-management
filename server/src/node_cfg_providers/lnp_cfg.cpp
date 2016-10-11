#include "lnp_cfg.h"
#include "cfg_helpers.h"
#include "log.h"

void lnp_cfg_provider::configure(cfg_t *cfg)
{
	dbg("configure lnp");
	cfg_t *c;

	c = cfg_getsec(cfg,"lnp");
	if(!c){
		info("no section for lnp nodes. skip configuration");
		throw std::exception();
	}

	//globals
	apply_section(cfg_getsec(c,"globals"),"",false,keys);

	//apply overrides
	for(int j = 0; j < cfg_size(c, "node"); j++){
		int node_id;
		cfg_t *node_cfg = cfg_getnsec(c,"node",j);
		if(0==sscanf(cfg_title(node_cfg),"%d",&node_id)){
			err("invalid lnp node id: '%s'",cfg_title(node_cfg));
			throw std::string("invalid lnp node id");
		}

		std::pair <override_t::iterator, bool> i =
			keys_override.insert(make_pair(node_id,cfg_keys()));
		cfg_keys &k = i.first->second;
		k = keys; //copy global values to node-specific config
		apply_section(node_cfg,"",true,k);
	}

	if(keys_override.empty()){
		err("no any lnp nodes");
		throw std::exception();
	}

	dbg("loaded %ld lnp nodes overrides",keys_override.size());
}

static inline std::string get_key(cfg_opt_t *c, std::string prefix){
	std::string s;
	if(!prefix.empty()){
		s = prefix;
		s.append(".");
	}
	s.append(c->name);
	return s;
}

void lnp_cfg_provider::apply_section(cfg_t *section, std::string prefix, bool overrides, cfg_keys &out)
{
	if(!section) return;

	cfg_opt_t *c = section->opts;
	bool finish = false;
	while(!finish && c){
		switch(c->type){
		case CFGT_NONE:
			finish = true;
			break;
		case CFGT_SEC:
			apply_section(cfg_getsec(section,c->name),get_key(c,prefix),overrides,out);
			break;
		case CFGT_FUNC:
		case CFGT_PTR:
			break;
		default:
			if(!add2hash(section,get_key(c,prefix),c->name,out)
				&& !overrides)
			{
				dbg("missed mandatory field lnp.%s",get_key(c,prefix).c_str());
				throw internal_exception(500,"invalid configuration");
			}
		}
		c++;
	}
}

const cfg_provider::cfg_keys &lnp_cfg_provider::get_keys(int node_id) const
{
	if(keys_override.find(node_id)==keys_override.end()){
		throw cfg_provider::internal_exception(404,"unknown node");
	}
	return keys_override.at(node_id);
}

void lnp_cfg_provider::show_config() const
{
	for(const auto &i: keys_override){
		for(const auto &j: i.second){
			info("lnp_node%d.%s => %s",
				 i.first,j.first.c_str(),j.second.asString().c_str());
		}
	}
}
