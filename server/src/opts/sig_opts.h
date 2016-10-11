#pragma once

#include <confuse.h>

#include "yeti_opts.h"

cfg_opt_t sig_node_opts[] = {
	CFG_SEC((char*)"yeti",sig_yeti_opts,CFGF_NONE),
	CFG_END()
};

cfg_opt_t sig_opts[] = {
	CFG_SEC((char*)"globals",sig_node_opts,CFGF_NONE),
	CFG_SEC((char*)"node",sig_node_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
	CFG_END()
};
