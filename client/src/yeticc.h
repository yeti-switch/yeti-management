#ifndef _YETI_CC_H_
#define _YETI_CC_H_

#include <netinet/in.h>

#include <string>
#include <list>
#include <map>

#include <cstring>

namespace yeti {

class base_exception: public std::exception
{
  protected:
	std::string _what;
  public:
	base_exception() throw() {}
	base_exception(const char *what) throw(): _what(what) {}
	~base_exception() throw() {}
	const char* what() const throw() { return _what.c_str(); }
};

namespace cfg {

struct arg_exception: public base_exception {
	arg_exception(const char *what) throw(): base_exception(what) {}
};

enum sock_op {
	s_op_create,
	s_op_send,
	s_op_recv,
};
struct socket_exception: public base_exception
{
	int e;
	enum sock_op op;
	socket_exception(sock_op operation, int error) throw();
};

struct server_exception: public base_exception {
	int code;
	server_exception(int c,const char *what) throw(): base_exception(what), code(c) {}
};

class reader
{
	typedef std::list<std::string> url_list;
	typedef std::map<int, url_list> urls_t;
	urls_t urls;
	int _timeout;

	int node_id;
	std::string cfg_part;

  public:

	reader();
	reader(int id,std::string part);
	~reader();

	void load();

	void add_url(const char *url,int priority = 1);
	void clear_urls();

	void set_timeout(int timeout) { _timeout = timeout; }
	void set_node_id(int id) { node_id = id; }
	void set_cfg_part(const std::string &part) { cfg_part = part; }

	int get_timeout() { return _timeout; }
	int get_node_id() { return node_id; }
	const std::string &get_cfg_part() { return cfg_part; }

	virtual void on_key_value_param(const std::string &name,const std::string &value) {}
	virtual void on_key_value_param(const std::string &name, int value);
};

} //yeti::cfg
} //yeti

#endif
