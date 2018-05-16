#include "HttpServer.h"

#include "log.h"

#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/eventfd.h>

static void
stop_event_cb(evutil_socket_t, short, void *arg)
{
    struct event_base *ev_base = (struct event_base *)arg;
    event_base_loopbreak(ev_base);
}

HttpServer::HttpServer()
  : ev_base(nullptr),
    ev_http(nullptr),
    ev_http_handle(nullptr)
{}

HttpServer::~HttpServer()
{
    if(ev_base)
        event_base_free(ev_base);
}

int HttpServer::http_init(cfg_t *http_cfg)
{
    ev_base = event_base_new();
    if (!ev_base) {
        err("couldn't create an event_base");
        return 1;
    }

    ev_http = evhttp_new(ev_base);
    if (!ev_http) {
        err("couldn't create evhttp");
        return 1;
    }

    evhttp_set_allowed_methods(ev_http, EVHTTP_REQ_GET | EVHTTP_REQ_POST | EVHTTP_REQ_HEAD);
#if LIBEVENT_VERSION_NUMBER >= 0x01090000
    evhttp_set_default_content_type(ev_http,"text/plain");
#endif

#if 0
    evhttp_set_cb(
        ev_http, "/rpc",
        [](struct evhttp_request *req, void *arg) {
            static_cast<HttpServer *>(arg)->rpc_request_cb(req);
        }, this);
#endif

    evhttp_set_cb(
        ev_http, "/status",
        [](struct evhttp_request *req, void *arg) {
            static_cast<HttpServer *>(arg)->status_request_cb(req);
        }, this);

    char *address = cfg_getstr(http_cfg,"address");
    int port = cfg_getint(http_cfg,"port");

    ev_http_handle = evhttp_bind_socket_with_handle(ev_http, address, port);
    if(!ev_http_handle) {
        err("couldn't bind http server to %s:%d",address,port);
        return 1;
    }

    dbg("bind socket to: %s:%d",address,port);

    int flags = EFD_NONBLOCK | EFD_SEMAPHORE;
    if((http_queue_event_fd = eventfd(0, flags)) == -1)
        err("failed to create eventfd");

    struct event * http_queue_event =
        event_new(ev_base, http_queue_event_fd, EV_READ | EV_PERSIST,
            [](evutil_socket_t, short, void *arg) {
                static_cast<HttpServer *>(arg)->on_http_queue_event_cb();
            }, this);

    if(!http_queue_event)
        err("failed to create http queue event");

    event_add(http_queue_event, NULL);

    return 0;
}

void HttpServer::http_start()
{
    std::thread t([this] { http_run(); });
    http_thread.swap(t);
}

void HttpServer::http_stop()
{
    /*uint64_t u = 1;
    write(http_stop_fd, &u, sizeof(uint64_t));*/
    http_post_event(new HttpEventTerminate());
    http_thread.join();
}

void HttpServer::http_run()
{
    pthread_setname_np(__gthread_self(), "http-server");
    event_base_dispatch(ev_base);
    dbg("HTTP server stopped");
}

#if 0
void HttpServer::rpc_request_cb(struct evhttp_request *req)
{
    struct evkeyvalq *headers;
    struct evkeyval *header;
    struct evbuffer *buf;

    dbg("received /rpc request");

    if(EVHTTP_REQ_HEAD==evhttp_request_get_command(req)) {
        evhttp_send_reply(req, HTTP_OK, "OK", nullptr);
        return;
    }

    headers = evhttp_request_get_input_headers(req);
    /*for (header = headers->tqh_first; header;
        header = header->next.tqe_next) {
        dbg("  %s: %s\n", header->key, header->value);
    }*/

    buf = evhttp_request_get_input_buffer(req);

    dbg("Input data: <<<");
    while (evbuffer_get_length(buf)) {
        int n;
        char cbuf[128];
        n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
        if (n > 0)
            dbg("%d: %.*s",n,n,cbuf);
    }
    dbg(">>>");

    struct evbuffer *out = evhttp_request_get_output_buffer(req);
    evbuffer_add_printf(out, "{ \"test\": 2 }\n");
    evhttp_send_reply(req, HTTP_OK, "OK", out);
}
#endif

void HttpServer::status_request_cb(struct evhttp_request *req)
{
    //dbg("received /status request");

    if(EVHTTP_REQ_HEAD==evhttp_request_get_command(req)) {
        evhttp_send_reply(req, HTTP_OK, "OK", nullptr);
        return;
    }

#if LIBEVENT_VERSION_NUMBER < 0x01090000
    evhttp_add_header(evhttp_request_get_output_headers(req),
                      "Content-Type","text/plain");
#endif

    evhttp_send_reply_start(req, HTTP_OK, "OK");

    on_http_stats_request(req);
}

void HttpServer::http_post_event(HttpEventBase *ev)
{
    uint64_t u = 1;

    std::lock_guard<std::mutex> lk(http_events_queue_mutex);

    http_events_queue.push(ev);
    write(http_queue_event_fd, &u, sizeof(uint64_t));
}

void HttpServer::on_http_queue_event_cb()
{
    uint64_t u;

    ::read(http_queue_event_fd, &u, sizeof(uint64_t));

    std::lock_guard<std::mutex> lk(http_events_queue_mutex);

    while(!http_events_queue.empty()) {
        HttpEventBase *ev = http_events_queue.front();
        http_events_queue.pop();
        http_process(ev);
        delete ev;
    }
}

#define ON_EVENT_TYPE(type) if(type *e = dynamic_cast<type *>(ev))

void HttpServer::http_process(HttpEventBase *ev)
{
    ON_EVENT_TYPE(HttpEventTerminate) {
        event_base_loopbreak(ev_base);
        return;
    }

    ON_EVENT_TYPE(HttpEventReply) {
        /*evhttp_send_reply(e->req, 200, "OK", e->reply_body);*/
        if(e->reply_body)
            evhttp_send_reply_chunk(e->req,e->reply_body);
        evhttp_send_reply_end(e->req);
        if(e->reply_body)
            evbuffer_free(e->reply_body);
        return;
    }
}

