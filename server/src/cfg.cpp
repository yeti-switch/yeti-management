#include "cfg.h"
#include "log.h"

#include "opts/sig_opts.h"
#include "opts/lnp_opts.h"
#include "opts/daemon_opts.h"

#define DEFAULT_PID_FILE "/var/run/yeti_management.pid"

cfg_opt_t system_opts[] = {
	CFG_SEC((char*)"signalling",sig_opts,CFGF_NONE),
	CFG_SEC((char*)"lnp",lnp_opts,CFGF_NONE),
	CFG_FUNC((char *)"include", &cfg_include),
	CFG_END()
};

cfg_opt_t daemon_opts[] = {
	CFG_SEC((char *)"daemon",daemon_section_opts,CFGF_NONE),
	CFG_END()
};

struct global_cfg_t cfg;

global_cfg_t::global_cfg_t():
	daemonize(true),
	pid(0),
	pid_file(0)
{}
