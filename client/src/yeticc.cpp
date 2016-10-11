#include "yeticc.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <linux/errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include "CfgRequest.pb.h"
#include "CfgResponse.pb.h"

#ifndef err
#define err(fmt,args...) printf("error: "fmt"\n",##args);
#endif

#define DEFAULT_SOCKET_TIMEOUT	3000	//miliseconds

using std::string;

static inline void shutdown_all(int s,const std::list<int> endpoints)
{
	for(std::list<int>::const_iterator i = endpoints.begin();
		i!=endpoints.end();++i)
			nn_shutdown(s,*i);
}

namespace yeti { namespace cfg {

socket_exception::socket_exception(sock_op operation, int error) throw():
	op(operation), e(error)
{
	switch(op){
	case s_op_create: _what.assign("nn_socket() "); break;
	case s_op_send: _what.assign("nn_send() "); break;
	case s_op_recv: _what.assign("nn_recv() "); break;
	}
	_what.append(nn_strerror(e));
}

reader::reader():
	_timeout(DEFAULT_SOCKET_TIMEOUT),
	node_id(0)
{ }

reader::reader(int id,std::string part):
	_timeout(DEFAULT_SOCKET_TIMEOUT),
	node_id(id),
	cfg_part(part)
{ }

reader::~reader()
{ }

void reader::load()
{
	int s, ret = -1,size;
	char *msg = NULL;

	if(urls.empty())
		throw arg_exception("have no urls");

	if((s = nn_socket(AF_SP, NN_REQ))<0)
		throw socket_exception(s_op_create,errno);

	nn_setsockopt(s,NN_SOL_SOCKET,NN_SNDTIMEO,&_timeout,sizeof(_timeout));
	nn_setsockopt(s,NN_SOL_SOCKET,NN_RCVTIMEO,&_timeout,sizeof(_timeout));

	std::list<int> connected_endpoints;
	for(urls_t::const_iterator j = urls.begin();
		j!=urls.end();++j)
	{
		int prio = j->first;
		const url_list &ul = j->second;

		nn_setsockopt(s, NN_SOL_SOCKET, NN_SNDPRIO, &prio, sizeof (int));

		for(url_list::const_iterator k = ul.begin();
			k!= ul.end();++k)
		{
			if(nn_connect(s, k->c_str())<0){
				continue;
			}
			connected_endpoints.push_back(ret);
		}
	}

	if(connected_endpoints.empty()){
		nn_close(s);
		throw arg_exception("no valid endpoints");
	}

	string bytes;
	try {
		CfgRequest c;
		c.set_node_id(node_id);
		c.set_cfg_part(cfg_part);

		if(!c.SerializeToString(&bytes)){
			throw base_exception("can't encode request");
		}
		ret = nn_send(s, bytes.data(), bytes.size(), 0);
	} catch(base_exception &e) {
		nn_close(s);
		throw e;
	}

	if(ret!=bytes.size()){
		nn_close(s);
		throw socket_exception(s_op_send,errno);
	}

	ret = nn_recv(s,&msg,NN_MSG,0);
	if(ret < 0){
		nn_close(s);
		throw socket_exception(s_op_recv,errno);
	}
	try {
		CfgResponse m;
		if(!m.ParseFromArray(msg,ret)){
			throw base_exception("can't decode response");
		}
		switch(m.Response_case()){
		case CfgResponse::kValues: {
			const google::protobuf::RepeatedPtrField< ::CfgResponse_ValuesPair >& v = m.values().values();
			for(google::protobuf::RepeatedPtrField< ::CfgResponse_ValuesPair >::const_iterator it = v.begin();
				it != v.end(); it++)
			{
				const CfgResponse_ValuesPair &p = *it;
				switch(p.Value_case()){
				case CfgResponse_ValuesPair::kI:
					on_key_value_param(p.name(),p.i());
					break;
				case CfgResponse_ValuesPair::kS:
					on_key_value_param(p.name(),p.s());
					break;
				default:
					//return empty string for unexpected values
					on_key_value_param(p.name(),string());
				}
			}
		} break;
		case CfgResponse::kError: {
			nn_freemsg(msg);
			nn_close(s);
			throw server_exception(
						m.error().code(),
						m.error().reason().c_str());
		} break;
		default:
			nn_freemsg(msg);
			nn_close(s);
			throw base_exception("unexpected response from server");
		}
	} catch(std::string &s){
		printf("exception: %s",s.c_str());
	}

	nn_freemsg(msg);
	nn_close(s);
}

void reader::add_url(const char *url,int priority)
{
	urls[priority].push_back(url);
}

void reader::clear_urls()
{
	urls.clear();
}

void reader::on_key_value_param(const std::string &name, int value)
{
	on_key_value_param(name,std::to_string(value));
}

} } //yeti::cfg
