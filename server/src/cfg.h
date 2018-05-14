#pragma once

#include "opts/opts.h"

#include <string>
using std::string;

#include <list>

#define EXIT_CFG_EXCEPTION 2

class cfg_exception
  : public std::exception
{
    std::string reason;
  public:
    cfg_exception(const std::string &s)
      : reason(s)
    { }
    const char* what() const noexcept { return reason.c_str(); }
};

struct global_cfg_t {
	bool daemonize;
	int pid;
	char *pid_file;
	std::list<string> bind_urls;
	global_cfg_t();
};

extern global_cfg_t cfg;

