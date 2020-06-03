#pragma once

#include <confuse.h>

#include "db_opts.h"
#include "redis_opts.h"
#include "statistics_opts.h"
#include "opts_helpers.h"

//routing
cfg_opt_t sig_yeti_routing_pool_opts[] = {
	db_opts,
	DCFG_INT(size),
	DCFG_INT(check_interval),
	DCFG_INT(max_exceptions),
	DCFG_INT(statement_timeout),
	CFG_END()
};

cfg_opt_t sig_yeti_routing_cache_opts[] = {
	DCFG_BOOL(enabled),
	DCFG_INT(check_interval),
	DCFG_INT(buckets),
	CFG_END()
};

cfg_opt_t sig_yeti_routing_opts[] = {
	DCFG_STR(schema),
	DCFG_STR(function),
	DCFG_STR(init),
	DCFG_BOOL(failover_to_slave),
	DCFG_BOOL(use_radius),
	DCFG_SEC(master_pool,sig_yeti_routing_pool_opts,CFGF_NONE),
	DCFG_SEC(slave_pool,sig_yeti_routing_pool_opts,CFGF_NONE),
	DCFG_SEC(cache,sig_yeti_routing_cache_opts,CFGF_NONE),
	CFG_END()
};


//cdr
cfg_opt_t sig_yeti_cdr_db_opts[] = {
	db_opts,
	CFG_END()
};

cfg_opt_t sig_yeti_cdr_opts[] = {
	DCFG_BOOL(failover_to_slave),
	DCFG_BOOL(failover_to_file),
	DCFG_BOOL(failover_requeue),
	DCFG_BOOL(serialize_dynamic_fields),
	DCFG_INT(pool_size),
	DCFG_INT(check_interval),
	DCFG_INT(batch_size),
	DCFG_INT(batch_timeout),
	DCFG_STR(dir),
	DCFG_STR(completed_dir),
	DCFG_STR(schema),
	DCFG_STR(function),
	DCFG_SEC(master,sig_yeti_cdr_db_opts,CFGF_NONE),
	DCFG_SEC(slave,sig_yeti_cdr_db_opts,CFGF_NONE),
	CFG_END()
};

//resources
cfg_opt_t sig_yeti_resources_pool_opts[] = {
	redis_pool_opts,
	CFG_END()
};

cfg_opt_t sig_yeti_resources_opts[] = {
	DCFG_BOOL(reject_on_error),
	DCFG_SEC(write,sig_yeti_resources_pool_opts,CFGF_NONE),
	DCFG_SEC(read,sig_yeti_resources_pool_opts,CFGF_NONE),
	CFG_END()
};

//rpc
cfg_opt_t sig_yeti_rpc_opts[] = {
	DCFG_INT(calls_show_limit),
	CFG_END()
};

//registrations
cfg_opt_t sig_yeti_reg_opts[] = {
	DCFG_INT(check_interval),
	CFG_END()
};

//registrar

cfg_opt_t sig_yeti_registrar_redis_opts[] = {
	DCFG_STR(host),
	DCFG_INT(port),
	CFG_END()
};

cfg_opt_t sig_yeti_registrar_opts[] = {
	DCFG_BOOL(enabled),
	DCFG_INT(expires_min),
	DCFG_INT(expires_max),
	DCFG_SEC(redis,sig_yeti_registrar_redis_opts,CFGF_NONE),
	CFG_END()
};

//auth
cfg_opt_t sig_yeti_auth_opts[] = {
	DCFG_STR(realm),
	CFG_END()
};

//yeti
cfg_opt_t sig_yeti_opts[] = {
	DCFG_INT(pop_id),
	DCFG_STR(msg_logger_dir),
	DCFG_STR(audio_recorder_dir),
	DCFG_BOOL(audio_recorder_compress),
	DCFG_STR(log_dir),
	DCFG_SEC(routing,sig_yeti_routing_opts,CFGF_NONE),
	DCFG_SEC(cdr,sig_yeti_cdr_opts,CFGF_NONE),
	DCFG_SEC(resources,sig_yeti_resources_opts,CFGF_NONE),
	DCFG_SEC(registrations,sig_yeti_reg_opts,CFGF_NONE),
	DCFG_SEC(registrar,sig_yeti_registrar_opts,CFGF_NONE),
	DCFG_SEC(rpc,sig_yeti_rpc_opts,CFGF_NONE),
	DCFG_SEC(statistics,sig_yeti_statistics_opts,CFGF_NONE),
	DCFG_SEC(auth,sig_yeti_auth_opts,CFGF_NONE),
	CFG_END()
};
