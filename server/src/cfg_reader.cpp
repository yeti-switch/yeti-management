#include "cfg_reader.h"

#include "log.h"
#include "cfg.h"

#include <errno.h>
#include <string.h>

cfg_reader::cfg_reader(cfg_opt_t *opts):
	_cfg(NULL),
	_opts(opts)
{}

cfg_reader::~cfg_reader()
{
	cfg_free(_cfg);
}

#define LOG_BUF_SIZE 2048
void cfg_reader_error(cfg_t *cfg, const char *fmt, va_list ap)
{
	char buf[LOG_BUF_SIZE];
	int ret = vsnprintf(buf,LOG_BUF_SIZE,fmt,ap);
	fprintf(stderr,"config_error: %.*s\n",ret,buf);
	err("%.*s",ret,buf);
}

bool cfg_reader::load(const char *path)
{
	bool ret = false;

	if(!_opts) return false;

	_cfg = cfg_init(_opts, CFGF_NONE);
	cfg_set_error_function(_cfg,cfg_reader_error);

	switch(cfg_parse(_cfg, path)) {
	case CFG_SUCCESS:
		break;
	case CFG_FILE_ERROR:
		err("configuration file: '%s' could not be read: %s",
			path, strerror(errno));
		goto out;
	case CFG_PARSE_ERROR:
		err("configuration file '%s' parse error", path);
		goto out;
	default:
		err("unexpected error on configuration file '%s' processing", path);
	}
	//cfg_print(cfg,stdout);
	ret = true;
out:
	return ret;
}

