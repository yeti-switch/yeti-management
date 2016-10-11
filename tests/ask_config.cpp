#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <yeticc.h>

using std::string;

class reader: public yeti::cfg::reader {
  public:
	reader(int id, std::string part): yeti::cfg::reader(id,part) {}
	void on_key_value_param(const string &name, const string &value){
		printf("%s = '%s'\n", name.c_str(), value.c_str());
	}
	void on_key_value_param(const string &name, int value){
		printf("%s = %d\n", name.c_str(), value);
	}
};

int main(int argc,char *argv[])
{
	int node_id = 0;

	if(argc<4) {
		printf("usage: %s url cfg_part node_id\n",
			   argv[0]);
		return EXIT_FAILURE;
	}

	if(1!=sscanf(argv[3],"%d",&node_id)){
		printf("can't cast node_id '%s' to integer",argv[3]);
		return EXIT_FAILURE;
	}

	try {
		reader cfg(node_id,argv[2]);

		/*for(int i = 1;i < argc; i++)
			cfg.add_url(argv[i]);*/
		cfg.add_url(argv[1]);

		cfg.set_timeout(500);
		cfg.load();
	} catch(yeti::cfg::server_exception &e){
		printf("%d %s\n",e.code,e.what());
	} catch(std::exception &e){
		printf("%s\n",e.what());
	}

	return EXIT_SUCCESS;
}
