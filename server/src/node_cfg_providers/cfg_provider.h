#pragma once

#include "log.h"

#include <confuse.h>

#include <map>
#include <string>
#include <cstring>

#include "CfgResponse.pb.h"

class cfg_value {
  public:
	enum {
		Undef = 0,
		Int,
		String
	};
  private:
	short type;
	union {
		long int	v_int;
		const char *v_str;
	};
  public:

	cfg_value(): type(Undef) {}

	cfg_value(const cfg_value& v);
	cfg_value& operator=(const cfg_value& v);

	cfg_value(const int &v): type(Int), v_int(v) {}
	cfg_value(const long int &v): type(Int), v_int(v) {}

	cfg_value(const char *v): type(String) { v_str = strdup(v); }
	cfg_value(const std::string &v): type(String) { v_str = strdup(v.c_str()); }

	void serialize(CfgResponse_ValuesPair *pair) const;

	template <typename T>
	inline T get() const;

	std::string asString() const;

	~cfg_value();
};

template<>
inline std::string cfg_value::get() const {
	switch(type){
	case String: return std::string(v_str); break;
	case Int: {
		char buf[64];
		int l = snprintf(buf,64,"%ld",v_int);
		return std::string(buf,l);
	} break;
	default: return std::string();
	}
}

class cfg_provider {
  public:
	struct internal_exception {
		int c;
		std::string e;
		internal_exception(int code, std::string error):
			c(code), e(error) {}
	};
	typedef std::map<std::string,cfg_value> cfg_keys;
  protected:
	cfg_keys keys;
	virtual const cfg_keys &get_keys(int node_id) const { return keys; }
  public:
	virtual void configure(cfg_t *cfg) = 0;
	virtual void serialize(CfgResponse_Values *v, int node_id) const;
	virtual void show_config() const = 0;
};

