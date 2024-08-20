#ifndef __DAEMON_H__
#define __DAEMON_H__

#include "network.h"
#include "log.h"
#include "config.h"

typedef struct {
  log_t*        log;
  network_t*    net;
  configure_t*  cfg;
}daemon_t;

extern daemon_t IKE;

void daemon_create();

#endif //__DAEMON_H__
