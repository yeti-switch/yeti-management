#pragma once

#include "cfg_provider.h"

#include <map>

class yeti_cfg_provider: public cfg_provider {
	typedef std::map<int,cfg_keys> override_t;
	override_t keys_override;

	void apply_cfg_node(cfg_t *in_cfg, cfg_keys &out_keys);
  protected:
	const cfg_keys &get_keys(int node_id) const;
  public:
	const cfg_keys &get_cfg(int node_id);
	void configure(cfg_t *cfg);
	void show_config() const;
};
