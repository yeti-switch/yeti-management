#include "cfg_provider.h"
#include "log.h"
#include <cstdlib>


cfg_value::~cfg_value(){
	switch(type){
	case String: free((void *)v_str); break;
	default: break;
	}
	type = Undef;
}

cfg_value::cfg_value(const cfg_value& v){
	type = Undef;
	*this = v;
}

cfg_value& cfg_value::operator=(const cfg_value& v) {
	type = v.type;
	switch(type){
	case Int: v_int = v.v_int; break;
	case String: v_str = strdup(v.v_str); break;
	case Undef: break;
	default: throw std::string("cfg_value: uknown rhs type");
	}
}

std::string cfg_value::asString() const { return get<std::string>(); }

void cfg_value::serialize(CfgResponse_ValuesPair *pair) const {
	//TODO: serialize to another types
	switch(type){
	case String:
		pair->set_s(v_str);
		break;
	case Int:
		pair->set_i(v_int);
		break;
	default:
		pair->set_i(0);
	}
}

void cfg_provider::serialize(CfgResponse_Values *v, int node_id) const {
	const cfg_keys &k = get_keys(node_id);
	for(const auto &i : k) {
		CfgResponse_ValuesPair *p = v->add_values();
		if(!p)
			throw internal_exception(500,"serialization error");
		p->set_name(i.first);
		i.second.serialize(p);
	}
}

