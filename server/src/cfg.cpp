#include "cfg.h"
#include "log.h"

struct global_cfg_t cfg;

#define DEFAULT_PID_FILE	"/var/run/yeti_management.pid"

global_cfg_t::global_cfg_t():
	daemonize(true),
	pid(0),
	pid_file(0)
{}
