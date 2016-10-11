#pragma once

#include "log.h"

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include "CfgRequest.pb.h"
#include "CfgResponse.pb.h"

#include <confuse.h>

#include <memory>
#include <string>
#include <list>
#include <map>
#include <cstring>

#include "node_cfg_providers/cfg_provider.h"
#include "cfg_reader.h"
#include "thread.h"

using std::string;

class mgmt_server {
	bool _stop;
	int s;
	static std::unique_ptr<mgmt_server> _self;
	//google::protobuf::LogSilencer pb_log_silencer;
	class cfg_providers_t : public std::map<std::string,cfg_provider *> {
	  public:
		~cfg_providers_t(){
			for(cfg_providers_t::const_iterator i = begin(); i != end(); ++i)
				delete i->second;
		}
	};
	cfg_providers_t cfg_providers;
	mutex cfg_mutex;

	mgmt_server();
	mgmt_server(mgmt_server const&);

	void operator=(mgmt_server const&);

	struct internal_exception {
		int c;
		string e;
		internal_exception(int code, string error):
			c(code), e(error) {}
	};

	int process_peer(char *msg, int len);
	void create_reply(string &reply, const CfgRequest &req);
	void create_error_reply(string &reply,int code, std::string description);

  public:
	static mgmt_server& instance(){
		if(_self.get()==0) _self.reset(new mgmt_server());
		return *_self;
	}
	void configure();
	void show_config();
	void loop(const std::list<string> &urls);
	void stop() { dbg_func(); _stop = true; }
};
