#pragma once

#include <thread>
#include <queue>
#include <mutex>

#include <event2/event.h>
#include <confuse.h>

#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include <functional>

struct HttpEventBase {
    virtual ~HttpEventBase() = default;
};

struct HttpEventTerminate
  : HttpEventBase
{ };

struct HttpEventReply
  : HttpEventBase
{
    struct evhttp_request *req;
    struct evbuffer *reply_body;
    HttpEventReply(struct evhttp_request *req, struct evbuffer *reply_body)
      : req(req),
        reply_body(reply_body)
    { }
};

class HttpServer
{
    struct event_base *ev_base;
    struct evhttp *ev_http;
    struct evhttp_bound_socket *ev_http_handle;

    std::thread http_thread;

    std::queue<HttpEventBase *> http_events_queue;
    std::mutex http_events_queue_mutex;
    int http_queue_event_fd;

  public:
    HttpServer();
    virtual ~HttpServer();

    int http_init(cfg_t *http_cfg);

    void http_start();
    void http_stop();
    void http_run();

    void http_post_event(HttpEventBase *ev);
    void http_process(HttpEventBase *ev);
    void on_http_queue_event_cb();

    //void rpc_request_cb(struct evhttp_request *req);
    void status_request_cb(struct evhttp_request *req);

    virtual void on_http_stats_request(struct evhttp_request *req) = 0;
};

