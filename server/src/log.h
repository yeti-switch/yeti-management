#pragma once

#include <syslog.h>
#include <cstdio>

#include <unistd.h>
#include <sys/syscall.h>

enum log_levels {
	L_ERR = 1,
	L_INFO,
	L_DBG,
};
extern volatile int log_level;

#ifdef VERBOSE_LOGGING
//#define _LOG(level,level_str,fmt,args...) syslog(level,"[%u] " level_str "%s:%d:%s " fmt ,syscall(__NR_gettid), __FILENAME__,__LINE__,__PRETTY_FUNCTION__,##args);
#define _LOG(level,level_str,fmt,args...) syslog(level,"[%lu] " level_str "%s:%d: " fmt ,syscall(__NR_gettid), __FILENAME__,__LINE__,##args);
#else
#define _LOG(level,level_str,fmt,args...) syslog(level,fmt,##args);
#endif

#define err(fmt,args...) _LOG(LOG_ERR,"error: ",fmt,##args);
#define cerr(fmt,args...) do { fprintf(stderr,"error: " fmt "\n",##args); err(fmt,##args); } while(0);
#define info(fmt,args...) if(log_level > L_ERR) _LOG(LOG_INFO,"info: ",fmt,##args);
#define dbg(fmt,args...) if(log_level > L_INFO) _LOG(LOG_DEBUG,"dbg: ",fmt,##args);

#define dbg_func(fmt,args...) dbg("%s " fmt,__PRETTY_FUNCTION__,##args);

void open_log();
void close_log();
