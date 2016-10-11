#pragma once

#include <confuse.h>

cfg_opt_t daemon_section_opts[] = {
	CFG_STR_LIST((char*)"listen",(char *)"{tcp://127.0.0.1:4444}",CFGF_NODEFAULT),
	CFG_INT((char *)"log_level",L_INFO, CFGF_NODEFAULT),
	CFG_END()
};
