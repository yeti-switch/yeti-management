#pragma once

#include <string>
using std::string;

#include <list>

struct global_cfg_t {
	bool daemonize;
	int pid;
	char *pid_file;
	std::list<string> bind_urls;
	global_cfg_t();
};

extern global_cfg_t cfg;

