#pragma once

#include "log.h"

#include <confuse.h>

#define SCTP_BUS_DEFAULT_PORT 10101

char sctp_bus_default_address[] = "127.0.0.1";

char opt_name_address[] = "address";
char opt_name_port[] = "port";

char section_name_sctp[] = "sctp";

cfg_opt_t sctp_section_opts[] = {
    CFG_STR(opt_name_address,sctp_bus_default_address,CFGF_NONE),
    CFG_INT(opt_name_port,SCTP_BUS_DEFAULT_PORT,CFGF_NONE),
    CFG_END()
};

cfg_opt_t daemon_section_opts[] = {
	CFG_STR_LIST((char*)"listen",(char *)"{tcp://127.0.0.1:4444}",CFGF_NODEFAULT),
	CFG_SEC(section_name_sctp,sctp_section_opts, CFGF_NODEFAULT),
	CFG_INT((char *)"log_level",L_INFO, CFGF_NODEFAULT),
	CFG_END()
};
