#include "yeti_cfg.h"
#include "cfg_helpers.h"
#include "log.h"

void yeti_cfg_provider::configure(cfg_t *cfg)
{
	dbg("configure yeti");
	cfg_t *c, *sig_cfg;

	sig_cfg = cfg_getsec(cfg,"signalling");
	if(!sig_cfg){
		info("no section for signalling nodes. skip configuration");
		return;
	}

	//globals
	c = cfg_getsec(sig_cfg,"globals");
	apply_cfg_node(c,keys);

	//apply overrides
	for(int j = 0; j < cfg_size(sig_cfg, "node"); j++){
		int node_id;
		cfg_t *node_cfg = cfg_getnsec(sig_cfg,"node",j);
		if(0==sscanf(cfg_title(node_cfg),"%d",&node_id)){
			err("invalid signalling node id: '%s'",cfg_title(node_cfg));
			throw std::string("invalid signalling node id");
		}

		std::pair <override_t::iterator, bool> i =
			keys_override.insert(make_pair(node_id,cfg_keys()));
		cfg_keys &k = i.first->second;
		k = keys; //copy global values to node-specific config
		apply_cfg_node(node_cfg,k);
	}

	dbg("loaded %ld signalling nodes overrides",keys_override.size());
}


inline void apply_pool_cfg(cfg_t *c,std::string prefix,
						   cfg_provider::cfg_keys &out)
{
	//apply_db_opts
	apply_db_cfg(c,prefix,out);
	//apply pool-specific opts
	add2hash(c,prefix+"pool_size","size",out);
	add2hash(c,prefix+"check_interval","check_interval",out);
	add2hash(c,prefix+"max_exceptions","max_exceptions",out);
	add2hash(c,prefix+"statement_timeout","statement_timeout",out);
}

void yeti_cfg_provider::apply_cfg_node(cfg_t *in_cfg,
									   cfg_provider::cfg_keys &out)
{
	//dbg("apply %p to %p",in_cfg,&out);
	cfg_t *c,*y = cfg_getsec(in_cfg,"yeti");
	//yeti
	add2hash(y,"pop_id","pop_id",out);
	add2hash(y,"msg_logger_dir","msg_logger_dir",out);
	add2hash(y,"audio_recorder_dir","audio_recorder_dir",out);
	add2hash(y,"audio_recorder_compress","audio_recorder_compress",out);
	add2hash(y,"log_dir","log_dir",out);
		//routing
		cfg_t *r = cfg_getsec(y,"routing");
		add2hash(r,"routing_schema","schema",out);
		add2hash(r,"routing_function","function",out);
		add2hash(r,"routing_init_function","init",out);
		add2hash(r,"failover_to_slave","failover_to_slave",out);
			//master pool
			apply_pool_cfg(cfg_getsec(r,"master_pool"),"master_",out);
			//slave pool
			apply_pool_cfg(cfg_getsec(r,"slave_pool"),"slave_",out);
			//cache
			c = cfg_getsec(r,"cache");
			add2hash(c,"profiles_cache_enabled","enabled",out);
			add2hash(c,"profiles_cache_check_interval","check_interval",out);
			add2hash(c,"profiles_cache_buckets","buckets",out);
		add2hash(r,"use_radius","use_radius",out);

		//cdr
		c = cfg_getsec(y,"cdr");
		add2hash(c,"cdr_failover_to_slave","failover_to_slave",out);
		add2hash(c,"failover_to_file","failover_to_file",out);
		add2hash(c,"failover_requeue","failover_requeue",out);
		add2hash(c,"serialize_dynamic_fields","serialize_dynamic_fields",out);
		add2hash(c,"cdr_pool_size","pool_size",out);
		add2hash(c,"cdr_dir","dir",out);
		add2hash(c,"writecdr_schema","schema",out);
		add2hash(c,"writecdr_function","function",out);
			//master
			apply_db_cfg(cfg_getsec(c,"master"),"mastercdr_",out);
			//slave
			apply_db_cfg(cfg_getsec(c,"slave"),"slavecdr_",out);

		//resources
		c = cfg_getsec(y,"resources");
		add2hash(c,"reject_on_cache_error","reject_on_error",out);
			//write
			apply_redis_pool_cfg(cfg_getsec(c,"write"),"write_redis_",out);
			//read
			apply_redis_pool_cfg(cfg_getsec(c,"read"),"read_redis_",out);

		//registrations
		c = cfg_getsec(y,"registrations");
		add2hash(c,"reg_check_interval","check_interval",out);

		//rpc
		c = cfg_getsec(y,"rpc");
		add2hash(c,"calls_show_limit","calls_show_limit",out);

		//statistics
		c = cfg_getsec(y,"statistics");
			c = cfg_getsec(c,"active-calls");
			add2hash(c,"active_calls_period","period",out);
				c = cfg_getsec(c,"clickhouse");
				add2hash(c,"active_calls_clickhouse_table","table",out);
				add2hash(c,"active_calls_clickhouse_queue","queue",out);
}

const cfg_provider::cfg_keys &yeti_cfg_provider::get_keys(int node_id) const
{
	if(keys_override.find(node_id)==keys_override.end()){
		throw cfg_provider::internal_exception(404,"unknown node");
	}
	return keys_override.at(node_id);
}

void yeti_cfg_provider::show_config() const
{
	for(const auto &i: keys_override){
		for(const auto &j: i.second){
			info("yeti_node%d.%s => %s",
				 i.first,j.first.c_str(),j.second.asString().c_str());
		}
	}
}
