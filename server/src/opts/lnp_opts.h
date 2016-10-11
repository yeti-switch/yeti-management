#pragma once

#include <confuse.h>

#include "opts_helpers.h"
#include "db_opts.h"
#include "daemon_opts.h"

cfg_opt_t lnp_section_db_opts[] = {
	db_opts,
	DCFG_INT(conn_timeout),
	DCFG_INT(check_interval),
	DCFG_STR(schema),
	CFG_END()
};

cfg_opt_t lnp_section_sip_opts[] = {
	VCFG_STR(contact_user,yeti-lnp-resolver),
	VCFG_STR(from_uri,sip:yeti-lnp-resolver@localhost),
	VCFG_STR(from_name,yeti-lnp-resolver),
	CFG_END()
};

cfg_opt_t lnp_section_opts[] = {
	DCFG_SEC(daemon,daemon_section_opts,CFGF_NONE),
	DCFG_SEC(db,lnp_section_db_opts,CFGF_NONE),
	DCFG_SEC(sip,lnp_section_sip_opts,CFGF_NONE),
	CFG_END()
};

cfg_opt_t lnp_opts[] = {
	DCFG_SEC(globals,lnp_section_opts,CFGF_NONE),
	DCFG_SEC(node,lnp_section_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
	CFG_END()
};
