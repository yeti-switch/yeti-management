#include "mgmt_server.h"

#include "node_cfg_providers/yeti_cfg.h"
#include "node_cfg_providers/lnp_cfg.h"

#include <map>
#include <list>

#include "cfg.h"

#define JSONRPC_TIMEOUT_SEC 3

std::unique_ptr<mgmt_server> mgmt_server::_self(nullptr);

class daemon_cfg_reader: public cfg_reader {
  public:
	daemon_cfg_reader():
		cfg_reader(daemon_opts)
	{}

	bool apply() {
		cfg_t *s;

		//daemon section
		s = cfg_getsec(_cfg,"daemon");
		for(int i = 0; i < cfg_size(s, "listen"); i++)
			cfg.bind_urls.push_back(cfg_getnstr(s, "listen", i));

		log_level = cfg_getint(s,"log_level");
		if(log_level < L_ERR) log_level = L_ERR;
		if(log_level > L_DBG) log_level = L_DBG;

		return true;
	}
};

class system_cfg_reader: public cfg_reader {
  public:
	system_cfg_reader():
		cfg_reader(system_opts)
	{}
};

mgmt_server::mgmt_server():
	_stop(false)
{ }

template<class T>
void add_provider(mgmt_server::cfg_providers_t &p, const char *name, cfg_t *cfg) {
	T *c = new T();
	try {
		c->configure(cfg);
	} catch(...){
		info("leave provider '%s' unconfigured",name);
		delete c;
		return;
	}
	p.insert(std::make_pair(name, c));
}

void mgmt_server::configure()
{
#define add_provider(name,type) add_provider<type>(tmp_cfg_providers,name,cfg)

	cfg_t *cfg;
	cfg_providers_t tmp_cfg_providers;
	std::pair<cfg_providers_t::iterator,bool> i;

	daemon_cfg_reader cr;
	if(!cr.load("/etc/yeti/management.cfg")){
		throw cfg_exception("can't load daemon config");
	}

	if(!cr.apply()){
		throw cfg_exception("can't apply daemon config");
	}

	cfg_t *daemon_section = cfg_getsec(cr.get_cfg(),"daemon");

	cfg_t *sctp_cfg = cfg_getsec(daemon_section,"sctp");
	if(!sctp_cfg)
		throw cfg_exception("missed 'daemon.sctp' section");
	if(sctp_init(sctp_cfg)) {
		throw std::string("failed to init sctp server");
	}

	cfg_t *http_cfg = cfg_getsec(daemon_section,"http");
	if(!http_cfg)
		throw cfg_exception("missed 'daemon.http' section");
	if(http_init(http_cfg)) {
		throw std::string("failed to init http server");
	}

	system_cfg_reader scr;
	if(!scr.load("/etc/yeti/system.cfg")){
		throw cfg_exception("can't load system config");
	}
	cfg = scr.get_cfg();

	add_provider("signalling",yeti_cfg_provider);
	add_provider("lnp",lnp_cfg_provider);

	if(tmp_cfg_providers.empty()){
		throw cfg_exception("there are no any configured providers");
	}

	cfg_mutex.lock();
	cfg_providers.swap(tmp_cfg_providers);
	cfg_mutex.unlock();

#undef add_provider
}

void mgmt_server::loop()
{
	dbg_func();

	pthread_setname_np(__gthread_self(), "mgmt-server");

	sctp_start();
	http_start();

	s = nn_socket(AF_SP,NN_REP);
	if(s < 0){
		throw std::string("nn_socket() = %d",s);
	}

	bool binded = false;
	if(cfg.bind_urls.empty()){
		throw std::string("no listen endpoints specified. check your config");
	}

	for(const auto &i : cfg.bind_urls) {
		const char *url = i.c_str();
		int ret = nn_bind(s, url);
		if(ret < 0){
			err("can't bind to url '%s': %d (%s)",url,
				 errno,nn_strerror(errno));
			continue;
		}
		binded = true;
		info("listen on %s",url);
	}

	if(!binded){
		err("there are no listened interfaces after bind. check log and your config");
		throw std::string("can't bind to any url");
	}

	while(!_stop){
		char *msg = NULL;
		int l = nn_recv(s, &msg, NN_MSG, 0);
		if(l < 0){
			if(errno==EINTR) continue;
			dbg("nn_recv() = %d, errno = %d(%s)",l,errno,nn_strerror(errno));
			//!TODO: handle timeout, etc
			continue;
		}
		process_peer(msg,l);
		nn_freemsg(msg);
	}

	sctp_stop();
	http_stop();
}

int mgmt_server::process_peer(char *msg, int len)
{
	string reply;
	CfgResponse cfg_reply;
	try {
		CfgRequest req;
		if(!req.ParseFromArray(msg,len)){
			throw std::string("can't decode request");
		}
		create_reply(cfg_reply,req);
		cfg_reply.SerializeToString(&reply);
	} catch(internal_exception &e){
		err("internal_exception: %d %s",e.c,e.e.c_str());
		create_error_reply(cfg_reply,e.c,e.e);
	} catch(std::string &e){
		err("%s",e.c_str());
		create_error_reply(cfg_reply,500,"Internal Error");
	}

	cfg_reply.SerializeToString(&reply);

	int l = nn_send(s, reply.data(), reply.size(), 0);
	if(l!=reply.size()){
		err("nn_send(): %d, while msg to send size was %ld",l,reply.size());
	}
	return 0;
}

void mgmt_server::create_error_reply(CfgResponse &reply,
									 int code, std::string description)
{
	dbg("reply with error: %d %s",code,description.c_str());
	CfgResponse_Error *e = reply.mutable_error();
	if(!e){
		dbg("can't mutate to error oneOf");
		return;
	}

	e->set_code(code);
	e->set_reason(description);
}

void mgmt_server::create_reply(CfgResponse &reply, const CfgRequest &req)
{
	info("process request for '%s' node %d",req.cfg_part().c_str(),req.node_id());

	CfgResponse_Values *v = reply.mutable_values();
	if(!v){
		throw internal_exception(500,"serialization error");
	}

	cfg_mutex.lock();

	//temporary hack for back-compatibiltiy (process 'sig_yeti' as 'signalling' )
	const string cfg_part = req.cfg_part()=="sig_yeti"?"signalling": req.cfg_part();

	//check for provider existence
	cfg_providers_t::const_iterator cfg_provider = cfg_providers.find(cfg_part);
	if(cfg_provider==cfg_providers.end()){
		cfg_mutex.unlock();
		throw internal_exception(404,"unknown cfg part");
	}

	//get and serialize config from appropriate config provider
	try {
		cfg_provider->second->serialize(v,req.node_id());
	} catch(cfg_provider::internal_exception &e){
		cfg_mutex.unlock();
		throw internal_exception(e.c,e.e);
	}

	cfg_mutex.unlock();
}

void mgmt_server::show_config(){
	cfg_mutex.lock();
	info("dump runtime configuration");
	for(const auto &i : cfg_providers){
		//info("  %s",i.first.c_str());
		i.second->show_config();
	}
	cfg_mutex.unlock();
}

void mgmt_server::on_http_stats_request(struct evhttp_request *req)
{
	std::lock_guard<std::mutex> lk(clients_mutex);

	if(clients.empty()) {
		//no connected nodes. sent empty reply
		dbg("no connected nodes. send empty reply");
		struct evbuffer *buf = evbuffer_new();
		evbuffer_add_printf(buf,"sctp_associations_count 0\n");
		http_post_event(new HttpEventReply(req,buf));
		return;
	}

	SctpBusPDU request;

	jsonrpc_cseq++;

	std::string &json = *request.mutable_payload();
	json = "{\"jsonrpc\":\"2.0\","
		   "\"method\":\"yeti.show.stats\","
		   "\"params\":{},"
		   "\"id\":\"" + std::to_string(jsonrpc_cseq) + "\"}";

	//dbg("created json: %s",json.c_str());

	request.set_type(SctpBusPDU::REQUEST);
	request.set_src_node_id(0);
	request.set_src_session_id("mgmt");
	request.set_dst_session_id("jsonrpc");

	jsonrpc_requests_mutex.lock();
	auto ret =
		jsonrpc_requests_by_cseq.emplace(jsonrpc_cseq,json_request_info());
	json_request_info &req_info = ret.first->second;

	gettimeofday(&req_info.expire_at, nullptr);
	req_info.expire_at.tv_sec += JSONRPC_TIMEOUT_SEC;
	req_info.req = req;
	req_info.cseq = jsonrpc_cseq;

	broadcast_json_request_unsafe(request,req_info);

	req_info.result =
		"sctp_associations_count "
		+ std::to_string(clients.size()) + '\n';

	if(req_info.sent_sctp_requests_assoc_id.empty()) {
		dbg("did not sent successfully to the any of the client. reply immediately");
		jsonrpc_requests_by_cseq.erase(jsonrpc_cseq);
		jsonrpc_requests_mutex.unlock();
		http_post_event(new HttpEventReply(req,nullptr));
		return;
	}

	jsonrpc_requests_mutex.unlock();
}

void mgmt_server::on_timer(struct timeval &now)
{
	jsonrpc_requests_mutex.lock();
	//check for jsonrpc requests timeout
	for(auto it = jsonrpc_requests_by_cseq.begin();
		it != jsonrpc_requests_by_cseq.end(); )
	{
		json_request_info &i = it->second;
		if(timercmp(&now,&i.expire_at,>)) {
			dbg("request with cseq %d expired",it->first);
			process_collected_json_replies(i,true);
			it = jsonrpc_requests_by_cseq.erase(it);
		} else {
			++it;
		}
	}
	jsonrpc_requests_mutex.unlock();

	SctpServer::on_timer(now);
}

bool mgmt_server::process_collected_json_replies(json_request_info &req_info, bool timeout)
{
    if(!timeout && !req_info.sent_sctp_requests_assoc_id.empty()) {
        /*dbg("we have more assocs without answer. "
            "skip processing and keep request in the map");*/
        return false;
    }

#if 0
    //debug only
    for(auto assoc : req_info.sent_sctp_requests_assoc_id) {
        dbg("request %d reply timeout from assoc %d",
            req_info.cseq, assoc);
    }
#endif

    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf,req_info.result.data(),req_info.result.size());
    http_post_event(new HttpEventReply(req_info.req,buf));

    return true; //remove request from the map
}
