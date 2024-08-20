#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "queue.h"
#include "chunk.h"

#include <stdint.h>

#define IPSTR_LEN 4*3+4

typedef uint32_t ip4_addr;

typedef struct {
  int       sock;
  int       port;
  queue_t*  q_send;
  queue_t*  q_recv;
}network_t;

network_t*  net_create();
void        net_free(network_t* net);
void        net_send(network_t* net, chunk_t* data, ip4_addr src, ip4_addr dst);
chunk_t*    net_recv(network_t* net, ip4_addr* src, ip4_addr* dst);

void        net_running(network_t* net);

ip4_addr    net_stoa(const char* ipstr);
void        net_atos(ip4_addr addr, char* ipstr, int len);

#endif //__NETWORK_H__
