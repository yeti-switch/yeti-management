#pragma once

#include "SctpBusPDU.pb.h"
#include "YetiEvent.pb.h"

#include "utils.h"
#include "cfg.h"

#include <stdint.h>
#include <confuse.h>
#include <limits.h>
#include <netinet/sctp.h>

#include <thread>
#include <mutex>
#include <string>
#include <map>
#include <unordered_map>

using std::string;
using std::map;

#define STATIC_BUFFER_SIZE USHRT_MAX
class SctpServer
{
    struct client_info {
        string host;
        short unsigned int port;
        int node_id;
        unsigned long events_received;
        client_info(const string &host, short unsigned int port)
          : host(host),
            port(port),
            node_id(-1),
            events_received(0)
        {}
    };
    typedef std::unordered_map<int,client_info> ClientsMap;
    ClientsMap clients;
    std::mutex clients_mutex;

    sockaddr_storage addr;
    char payload[STATIC_BUFFER_SIZE];

    typedef enum {
        Closed = 0,
        Connecting,
        Connected,
    } state_t;
    state_t state;

    int stop_event_fd;
    int timer_fd;
    int epoll_fd;
    int sctp_fd;
    std::thread _t;

    int sctp_configure(cfg_t *cfg);
    void run();
    int process(uint32_t events);
    void handle_notification(const sockaddr_storage &from);

    void onIncomingPDU(sctp_assoc_t assoc_id, const SctpBusPDU &e);
    void process_sctp_cfg_request(sctp_assoc_t assoc_id, const SctpBusPDU &e, const CfgRequest &req);
    int send_to_assoc(int assoc_id, void *payload, size_t payload_len);

    virtual void create_reply(CfgResponse &reply, const CfgRequest &req) = 0;
    virtual void create_error_reply(CfgResponse &reply,int code, std::string description) = 0;

  protected:
    struct internal_exception {
        int c;
        string e;
        internal_exception(int code, string error):
            c(code), e(error) {}
    };

  public:
    SctpServer();
    ~SctpServer();

    int sctp_init(cfg_t *cfg);
    void sctp_start();
    void on_stop();
    void on_timer();
};

