#pragma once

#include "cfg_provider.h"

#include <map>

class lnp_cfg_provider: public cfg_provider {
	typedef std::map<int,cfg_keys> override_t;
	override_t keys_override;

	void apply_section(cfg_t *in_cfg, std::string prefix, bool overrides, cfg_keys &out);
  protected:
	const cfg_keys &get_keys(int node_id) const;
  public:
	void configure(cfg_t *cfg);
	void show_config() const;
};
