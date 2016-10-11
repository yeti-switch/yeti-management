#pragma once

#include "sig_opts.h"
#include "lnp_opts.h"
#include "daemon_opts.h"

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
