#pragma once

#include <confuse.h>

class cfg_reader {
  protected:
	cfg_t *_cfg;
	cfg_opt_t *_opts;
  public:
	//cfg_reader();
	cfg_reader(cfg_opt_t *opts);
	~cfg_reader();

	bool load(const char *path);
	cfg_t *get_cfg() { return _cfg; }
};
