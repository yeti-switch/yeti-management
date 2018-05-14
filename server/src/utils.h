#pragma once

#include <string.h>
#include <errno.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <string>
using std::string;

void addr_set_port(struct sockaddr_storage* addr, short port);
unsigned short addr_get_port(const sockaddr_storage* addr);

const char* addr_inet_ntop(const sockaddr_storage* addr, char* str, size_t size);
string addr_inet_ntop(const sockaddr_storage* addr);
int addr_inet_pton(const char* src, struct sockaddr_storage* dst);
