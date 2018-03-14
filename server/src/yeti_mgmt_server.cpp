#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "log.h"
#include "cfg.h"
#include "version.h"
#include "mgmt_server.h"

#include <google/protobuf/stubs/common.h>

#define DEFAULT_PID_FILE "/var/run/yeti_management.pid"

void create_pid_file(){
	if(!cfg.pid) return;
	if(!cfg.pid_file) return;

	FILE* f = fopen(cfg.pid_file, "w");
	if(!f){
		cerr("can't create pid_file: '%s'",cfg.pid_file);
		exit(EXIT_FAILURE);
	}
	fprintf(f,"%d",cfg.pid);
	fclose(f);
}

void delete_pid_file(){
	if(!cfg.pid) return;
	if(!cfg.pid_file) return;
	if(!cfg.daemonize) return;

	FILE* f = fopen(cfg.pid_file, "r");
	if(!f){
		err("can't open own pid_file '%s'",cfg.pid_file);
		return;
	}

	int file_pid;
	if(fscanf(f,"%d",&file_pid)!=1){
		err("can't get pid from pid_file '%s'",cfg.pid_file);
		return;
	}

	if(cfg.pid!=file_pid){
		err("pid in '%s' doesn't matched with our own. skip unlink",cfg.pid_file);
		return;
	}
	unlink(cfg.pid_file);
}

void usage(){
#define opt(name,desc) "\n   -"#name" " desc
#define opt_ext(name,desc,ext) opt(name,desc)"\n         " ext
#define opt_arg(name,arg,desc) "\n   -"#name" <" arg "> " desc
#define opt_arg_ext(name,arg,desc,ext) opt_arg(name,arg,desc) "\n         " ext
	printf(
	"usage:"
		opt(h,"this help")
		opt(f,"run foreground (don't daemonize)")
		opt_arg_ext(p,"pid_file","use another pid file","default: " DEFAULT_PID_FILE)
	"\n"
	);
#undef opt_arg_ext
#undef opt_arg
#undef opt_ext
#undef opt
}

void parse_opts(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "vhfp:"))!=-1){ switch(c){
		case 'v': printf("%s\n",SERVER_VERSION); exit(EXIT_SUCCESS); break;
		case 'h': usage(); exit(EXIT_SUCCESS); break;
		case 'f': cfg.daemonize = false; break;
		case 'p': cfg.pid_file = optarg; break;
		case '?':
			switch(optopt){
			case NULL:
				continue;
				break;
			case 'p':
			case 'u':
				cerr("Option -%c requires an argument. use -h for details", optopt);
				break;
			default:
				if(isprint(optopt)) cerr("Unknown option `-%c'.",optopt)
				else cerr("Unknown option character `\\x%x'.",optopt);
			}
			exit(EXIT_FAILURE);
		default:
			abort();
	}}
}

void sig_handler(int sig){
	dbg("got sig = %d",sig);
	if(sig==SIGHUP){
		info("reload configuration");
		try {
			mgmt_server::instance().configure();
			info("configuration were successfully reloaded");
		} catch(std::string &e){
			err("configuration reload error: %s",e.c_str());
		} catch(...){
			err("uknown configuration reload error");
		}
		return;
	} else if(sig==SIGUSR1){
		mgmt_server::instance().show_config();
		return;
	}
	mgmt_server::instance().stop();
}

void set_sighandlers() {
	static int sigs[] = {SIGTERM, SIGINT, SIGHUP, SIGUSR1, 0 };
	for (int* sig = sigs; *sig; sig++) {
		if(signal(*sig, sig_handler) == SIG_IGN) signal(*sig,SIG_IGN);
	}
}


int main(int argc,char *argv[])
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	open_log();

	parse_opts(argc,argv);

	try {
		mgmt_server &srv = mgmt_server::instance();
		srv.configure();

		if(cfg.daemonize){
			if(!cfg.pid_file) cfg.pid_file = strdup(DEFAULT_PID_FILE);

			int pid;
			if ((pid=fork())<0){
				cerr("can't fork: %d, errno = %d",pid,errno);
			} else if(pid!=0) {
				return 0;
			}

			cfg.pid = getpid();
			create_pid_file();

			freopen("/dev/null", "w", stdout);
			freopen("/dev/null", "w", stderr);
		}
		freopen("/dev/null", "r", stdin);

		info("starting version %s",SERVER_VERSION);
		set_sighandlers();
		srv.loop(cfg.bind_urls);
	} catch(std::string &s){
		err("%s",s.c_str());
	} catch(std::exception &e) {
		err("%s\n",e.what());
	}

	delete_pid_file();

	info("terminated");
	close_log();

	google::protobuf::ShutdownProtobufLibrary();

	return 0;
}

