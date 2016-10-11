#include "log.h"

#define DAEMON_NAME "yeti-management"
#define DEFAULT_LOG_LEVEL	L_INFO;

volatile int log_level = DEFAULT_LOG_LEVEL;

void open_log(){
	openlog(DAEMON_NAME,LOG_PID,LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_DEBUG));
}

void close_log(){
	closelog();
}
