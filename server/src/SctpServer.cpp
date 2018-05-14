#include "SctpServer.h"

#include "log.h"

#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>

#include "YetiEvent.pb.h"

#include <vector>
using std::vector;

#define EPOLL_MAX_EVENTS    2048
#define TIMEOUT_CHECKING_INTERVAL 1000000 //microseconds

#define sctp_sys_err(fmt, args...) \
do { \
    err(fmt ": %m",##args); \
    return -1; \
} while(0)\

static void longlong2timespec(struct timespec &ts,unsigned long long msec)
{
  if(0==msec){
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    return;
  }
  ts.tv_sec = (time_t)(msec / 1000000ULL);
  ts.tv_nsec = (long)(1000ULL*(msec % 1000000ULL));
}

SctpServer::SctpServer()
  : epoll_fd(-1),
    sctp_fd(-1),
    state(Closed)
{}

SctpServer::~SctpServer()
{
    if(-1!=epoll_fd)
        close(epoll_fd);
}

int SctpServer::sctp_configure(cfg_t *cfg)
{
    struct sctp_event_subscribe event = {};
    int opt = 1;

    clients.clear();

    if(!addr_inet_pton(cfg_getstr(cfg,"address"),&addr)) {
        err("configuration error. invalid address '%s' in sctp section",
              cfg_getstr(cfg,"address"));
        return -1;
    }

    addr_set_port(&addr,cfg_getint(cfg,"port"));

    dbg("bind sctp socket to: %s:%d",addr_inet_ntop(&addr).c_str(),addr_get_port(&addr));

    if((sctp_fd = socket( AF_INET, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_SCTP)) < 0 )
        sctp_sys_err("socket()");

    if(setsockopt(sctp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        sctp_sys_err("setsockopt(SO_REUSEADDR)");

#ifdef SO_REUSEPORT // (since Linux 3.9)
    if(setsockopt(sctp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        sctp_sys_err("setsockopt(SO_REUSEPORT)");
#endif

    if(sctp_bindx(sctp_fd,(struct sockaddr *)&addr, 1, SCTP_BINDX_ADD_ADDR) < 0)
        sctp_sys_err("sctp_bindx()");

    /** enable all SCTP event notifications */
    event.sctp_data_io_event        = 1;
    event.sctp_association_event    = 1;
    event.sctp_address_event        = 1;
    event.sctp_send_failure_event   = 1;
    event.sctp_peer_error_event     = 1;
    event.sctp_shutdown_event       = 1;
    event.sctp_partial_delivery_event = 1;
    event.sctp_adaptation_layer_event = 1;

    if(setsockopt(sctp_fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event)) < 0)
        sctp_sys_err("setsockopt(IPPROTO_SCTP)");

    if(listen(sctp_fd, 20) != 0)
        sctp_sys_err("listen()");

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data = {
            .fd = -sctp_fd
        }
    };

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sctp_fd, &ev) == -1)
        sctp_sys_err("epoll_ctl(EPOLL_CTL_ADD)");

    /*if(0!=server_connection.init(epoll_fd,a)) {
        err("failed to init sctp server connection");
        return -1;
    }*/

    dbg("SctpBus configured");

    return 0;
}

int SctpServer::sctp_init(cfg_t *cfg) {

    dbg_func();
    //AmPlugIn::registerDIInterface(getName(),this);

    if((epoll_fd = epoll_create(10)) == -1) {
        throw std::string("epoll_create failed");
        return -1;
    }

    if((timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK)) == -1)
      throw string("timerfd. timerfd_create call failed");

    struct itimerspec tmr;
    longlong2timespec(tmr.it_value,TIMEOUT_CHECKING_INTERVAL);
    tmr.it_interval = tmr.it_value;
    if(timerfd_settime(timer_fd,0,&tmr,NULL))
        throw string("timerfd. timer set failed");;

    int flags = EFD_NONBLOCK | EFD_SEMAPHORE;
    if((stop_event_fd = eventfd(0, flags)) == -1)
        throw string("eventfd. eventfd call failed");

    struct epoll_event ev;
    ev.events = EPOLLIN;

    ev.data.fd = -stop_event_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stop_event_fd, &ev) == -1){
        throw string("failed to link stop_event to the epoll");
    }

    ev.data.fd = -timer_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) == -1){
        throw string("failed to link timer to the epoll");
    }

    if(-1==sctp_configure(cfg))
        return -1;

    dbg("SctpBus initialized");

    return 0;
}

void SctpServer::sctp_start()
{
    std::thread t([this] { run(); });
    _t.swap(t);
}

void SctpServer::run()
{
    int ret,f;
    bool running;
    uint64_t u;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    pthread_setname_np(__gthread_self(), "sctp-bus");

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret < 1) {
            if(errno != EINTR){
                err("epoll_wait: %m");
            }
            continue;
        }

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            f = e.data.fd;
            if(f==-timer_fd) {
                on_timer();
                ::read(timer_fd, &u, sizeof(uint64_t));
            /*} else if(f== -queue_fd()){
                clear_pending();
                processEvents(); */
            } else if(f==-sctp_fd) {
                process(e.events);
            } else if(f==-stop_event_fd){
                ::read(stop_event_fd, &u, sizeof(uint64_t));
                running = false;
                break;
            } else {
                dbg("got event for unknown fd: %d",f);
            }
        }
    } while(running);

    close(epoll_fd);
    close(stop_event_fd);
    close(timer_fd);

    dbg("SctpBus stopped");
}

void SctpServer::on_stop()
{
    uint64_t u = 1;
    write(stop_event_fd, &u, sizeof(uint64_t));
    _t.join();
}

void SctpServer::on_timer()
{
    //dbg("on_timer");
    clients_mutex.lock();
    for(const auto &client : clients) {
        const client_info &info = client.second;
        dbg("assoc_id: %d, remote_host: %s, remote_port: %d, "
            "node_id: %d, events_received: %ld",
            client.first,
            info.host.c_str(), info.port,
            info.node_id, info.events_received);
    }
    clients_mutex.unlock();
}

void SctpServer::handle_notification(const sockaddr_storage &from)
{
    const char *str;
    const auto sn = (sctp_notification *)payload;

    switch(sn->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE: {
        const auto &sac = sn->sn_assoc_change;
        switch(sac.sac_state) {
        case SCTP_COMM_UP:
            str = "COMMUNICATION UP";
            info("associated with %s:%u/%d (%d)",
                 addr_inet_ntop(&from).c_str(),addr_get_port(&from),
                 sac.sac_assoc_id,sctp_fd);
            clients_mutex.lock();
            clients.emplace(sac.sac_assoc_id,
                            client_info(
                               addr_inet_ntop(&from),
                               addr_get_port(&from)));
            clients_mutex.unlock();
            break;
        case SCTP_COMM_LOST:
            str = "COMMUNICATION LOST";
            clients_mutex.lock();
            clients.erase(sac.sac_assoc_id);
            clients_mutex.unlock();
            break;
        case SCTP_RESTART:
            str = "RESTART";
            break;
        case SCTP_SHUTDOWN_COMP:
            str = "SHUTDOWN COMPLETE";
            clients_mutex.lock();
            clients.erase(sac.sac_assoc_id);
            clients_mutex.unlock();
            break;
        case SCTP_CANT_STR_ASSOC:
            str = "CANT START ASSOC";
            err("SCTP_CANT_STR_ASSOC, assoc=%u",sac.sac_assoc_id);
        default:
            str = "UNKNOWN";
        } //switch(sac.sac_state)
        dbg("SCTP_ASSOC_CHANGE: %s, assoc=%u",str,sac.sac_assoc_id);
    } break; //case SCTP_ASSOC_CHANGE
    case SCTP_PEER_ADDR_CHANGE: {
        const auto &spc = sn->sn_paddr_change;
        switch(spc.spc_state) {
        case SCTP_ADDR_AVAILABLE:
            str = "ADDRESS AVAILABLE";
            break;
        case SCTP_ADDR_UNREACHABLE:
            str = "ADDRESS UNAVAILABLE";
            break;
        case SCTP_ADDR_REMOVED:
            str = "ADDRESS REMOVED";
            break;
        case SCTP_ADDR_ADDED:
            str = "ADDRESS ADDED";
            break;
        case SCTP_ADDR_MADE_PRIM:
            str = "ADDRESS MADE PRIMARY";
            break;
        case SCTP_ADDR_CONFIRMED:
            str = "CONFIRMED";
            break;
        default:
            str = "UNKNOWN";
        } //switch(spc.spc_state)
        dbg("SCTP_PEER_ADDR_CHANGE: %s, assoc=%u",str,spc.spc_assoc_id);
    } break; //case SCTP_PEER_ADDR_CHANGE
    case SCTP_REMOTE_ERROR: {
        const auto &sre = sn->sn_remote_error;
        err("SCTP_REMOTE_err: assoc=%u", sre.sre_assoc_id);
    } break;
    case SCTP_SEND_FAILED: {
        const auto &ssf = sn->sn_send_failed;
        err("SCTP_SEND_FAILED: assoc=%u", ssf.ssf_assoc_id);
    } break;
    case SCTP_ADAPTATION_INDICATION: {
        const auto &ae = sn->sn_adaptation_event;
        dbg("SCTP_ADAPTATION_INDICATION bits:0x%x", ae.sai_adaptation_ind);
    } break;
    case SCTP_PARTIAL_DELIVERY_EVENT: {
        const auto &pdapi = sn->sn_pdapi_event;
        dbg("SCTP_PD-API event:%u", pdapi.pdapi_indication);
        if(pdapi.pdapi_indication == 0)
            dbg("PDI- Aborted");
    } break;
    case SCTP_SHUTDOWN_EVENT: {
        const auto &sse = sn->sn_shutdown_event;
        dbg("SCTP_SHUTDOWN_EVENT: assoc=%u", sse.sse_assoc_id);
        clients_mutex.lock();
        clients.erase(sse.sse_assoc_id);
        clients_mutex.unlock();
    } break;
    default:
        err("Unknown notification event type=%xh",sn->sn_header.sn_type);
    } //switch(snp->sn_header.sn_type)
}

int SctpServer::process(uint32_t events)
{
    int flags = 0, length;
    struct sctp_sndrcvinfo  sinfo;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(struct sockaddr);

    length = sctp_recvmsg(sctp_fd, payload, sizeof(payload)-1,
                          (struct sockaddr *)&from,
                          &fromlen,
                          &sinfo,
                          &flags);

    if( length < 0 ) {
        err("sctp_recvmsg(): %m");
        return errno;
    }

    if(0/*reject condition*/) {
        err("not allowed from %s",addr_inet_ntop(&from).c_str());
        sinfo.sinfo_flags = SCTP_EOF;
        sctp_send(sctp_fd, NULL, 0, &sinfo, MSG_NOSIGNAL);
    }

    if(flags & MSG_NOTIFICATION) {
        handle_notification(from);
        return 0;
    }

    // catch only FULL SIZE message
    //!TODO: implement fragments reassembling
    if(!(flags & MSG_EOR) ) {
        err("Truncated message received");
        return 0;
    }

    SctpBusPDU e;
    if(!e.ParseFromArray(payload,length)){
        err("failed deserialize request");
        return -1;
    }

    dbg("RECV sctp_bus event %d:%s -> %d:%s/%d, seq: %ld",
        e.src_node_id(),
        e.src_session_id().c_str(),
        e.dst_node_id(),
        e.dst_session_id().c_str(),
        sinfo.sinfo_assoc_id,
        e.has_sequence()? e.sequence() : -1);

    clients_mutex.lock();
    ClientsMap::iterator it = clients.find(sinfo.sinfo_assoc_id);
    if(it == clients.end()) {
        err("got event from assoc id: %d which not exists in clients hash",
            sinfo.sinfo_assoc_id);
        clients_mutex.unlock();
        return -1;
    }

    client_info &cinfo = it->second;
    cinfo.node_id = e.src_node_id();
    cinfo.events_received++;

    clients_mutex.unlock();

    onIncomingPDU(sinfo.sinfo_assoc_id,e);

    return 0;
}

void SctpServer::onIncomingPDU(sctp_assoc_t assoc_id, const SctpBusPDU &e)
{
    //dbg("on incoming PDU");

    YetiEvent y_ev;
    if(!y_ev.ParseFromString(e.payload())) {
        err("failed to deserialize SctpBusPDU payload with size: %ld",e.payload().size());
        return;
    }

    dbg("got yeti event: %d",y_ev.data_case());
    switch(y_ev.data_case()) {
    case YetiEvent::kCfgRequest:
        process_sctp_cfg_request(assoc_id,e,y_ev.cfg_request());
        break;
    case YetiEvent::kJson:
        dbg("got json event: %s",
            y_ev.json().c_str());
        break;
    default:
        err("got unsupported yeti event: %d",y_ev.data_case());
    }
}

static void fill_sctp_reply(SctpBusPDU &reply, const SctpBusPDU &req)
{
    reply.set_type(SctpBusPDU::REPLY);
    reply.set_sequence(req.sequence());
    reply.set_src_node_id(req.dst_node_id());
    reply.set_src_session_id(req.dst_session_id());
    reply.set_dst_node_id(req.src_node_id());
    reply.set_dst_session_id(req.src_session_id());
}

void SctpServer::process_sctp_cfg_request(sctp_assoc_t assoc_id, const SctpBusPDU &e, const CfgRequest &req)
{
    SctpBusPDU reply;
    //string cfg_reply;
    YetiEvent y;
    string reply_payload;

    CfgResponse &cfg_reply = *y.mutable_cfg_response();

    try {
        create_reply(cfg_reply,req);
    } catch(internal_exception &e){
        err("internal_exception: %d %s",e.c,e.e.c_str());
        create_error_reply(cfg_reply,e.c,e.e);
    } catch(std::string &e){
        err("%s",e.c_str());
        create_error_reply(cfg_reply,500,"Internal Error");
    }

    y.SerializeToString(&reply_payload);

    fill_sctp_reply(reply,e);
    reply.set_payload(reply_payload);

    if(!reply.SerializeToArray(payload,STATIC_BUFFER_SIZE)) {
        err("failed to serialize event");
        return;
    }

    if(-1==send_to_assoc(assoc_id, payload, reply.GetCachedSize())) {
        err("send_to_assoc: %d",errno);
    }
}

int SctpServer::send_to_assoc(int assoc_id, void *payload, size_t payload_len)
{
    struct sctp_sndrcvinfo sinfo = { };
    struct msghdr outmsg;
    struct cmsghdr *cmsg;
    char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];

    sinfo.sinfo_assoc_id = assoc_id;

    struct iovec iov[1] = {{ .iov_base = payload, .iov_len = payload_len }};
    int iov_len = 1;

    outmsg.msg_name = NULL;
    outmsg.msg_namelen = 0;
    outmsg.msg_iov = iov;
    outmsg.msg_iovlen = iov_len;

    outmsg.msg_control = outcmsg;
    outmsg.msg_controllen = sizeof(outcmsg);
    outmsg.msg_flags = 0;

    cmsg = CMSG_FIRSTHDR(&outmsg);
    cmsg->cmsg_level = IPPROTO_SCTP;
    cmsg->cmsg_type = SCTP_SNDRCV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

    outmsg.msg_controllen = cmsg->cmsg_len;
    memcpy(CMSG_DATA(cmsg), &sinfo, sizeof(struct sctp_sndrcvinfo));

    return ::sendmsg(sctp_fd, &outmsg, SCTP_UNORDERED | MSG_NOSIGNAL);
}
