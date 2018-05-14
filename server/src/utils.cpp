#include "utils.h"
#include "log.h"

void addr_set_port(struct sockaddr_storage* addr, short port)
{
    if(addr->ss_family == AF_INET) {
        reinterpret_cast<struct sockaddr_in *>(addr)->sin_port = htons(port);
    } else {
        reinterpret_cast<struct sockaddr_in6 *>(addr)->sin6_port = htons(port);
    }
}

unsigned short addr_get_port(const sockaddr_storage* addr)
{
    if(addr->ss_family == AF_INET) {
        return ntohs(reinterpret_cast<const struct sockaddr_in *>(addr)->sin_port);
    }
    return ntohs(reinterpret_cast<const struct sockaddr_in6 *>(addr)->sin6_port);
}

const char* addr_inet_ntop(const sockaddr_storage* addr, char* str, size_t size) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

    if(addr->ss_family == AF_INET) {
        if(!inet_ntop(AF_INET,&sin->sin_addr,str,size)) {
            err("Could not convert IPv4 address to string: %s",strerror(errno));
            return NULL;
        }
    } else if(!inet_ntop(AF_INET6,&sin6->sin6_addr,str,size)) {
        err("Could not convert IPv6 address to string: %s",strerror(errno));
        return NULL;
    }

    return str;
}

string addr_inet_ntop(const sockaddr_storage* addr) {
    char host[NI_MAXHOST] = "";
    addr_inet_ntop(addr,host,NI_MAXHOST);
    return host;
}

int addr_inet_pton(const char* src, struct sockaddr_storage* dst)
{
    char src_addr[NI_MAXHOST];

    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    bool must_be_ipv6 = false;

    if(!src)
        return 0;

    size_t src_len = strlen(src);
    if(!src_len || (src_len > NI_MAXHOST-1))
        return 0;

    if( (src[0] == '[') &&
        (src[src_len-1] == ']') )
    {
        // IPv6
        memcpy(src_addr,src+1,src_len-2);
        src_addr[src_len-2] = '\0';
        must_be_ipv6 = true;
    } else {
        // IPv4
        memcpy(src_addr,src,src_len+1);
    }

    sin = (struct sockaddr_in *)dst;
    sin6 = (struct sockaddr_in6 *)dst;

    if(!must_be_ipv6 && (inet_pton(AF_INET, src_addr, &sin->sin_addr) > 0)) {
        dst->ss_family = AF_INET;
        return 1;
    }

    if(inet_pton(AF_INET6, src_addr, &sin6->sin6_addr) > 0) {
        dst->ss_family = AF_INET6;
#ifdef SIN6_LEN
        sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
        return 1;
    }

    return 0;
}
