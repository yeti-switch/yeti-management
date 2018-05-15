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

#include "SctpServer.h"
#include "HttpServer.h"

using std::string;

class mgmt_server
  : public SctpServer,
    public HttpServer
{
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

	int process_peer(char *msg, int len);
	void create_reply(CfgResponse &reply, const CfgRequest &req);
	void create_error_reply(CfgResponse &reply,int code, std::string description);

  protected:
    bool process_collected_json_replies(json_request_info &req_info, bool timeout);

  public:
	static mgmt_server& instance(){
		if(_self.get()==0) _self.reset(new mgmt_server());
		return *_self;
	}
	void configure();
	void show_config();
	void loop();
	void stop() { dbg_func(); _stop = true; }

	void on_http_stats_request(struct evhttp_request *req) override;
	void on_timer(struct timeval &) override;
};
