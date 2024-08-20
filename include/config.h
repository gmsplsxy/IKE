#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <libconfig.h>
#include "network.h"

typedef struct {
  struct {
    ip4_addr addr;
  }left, right;
}configure_t;

configure_t* cfg_create(const char* filename);

#endif //__CONFIG_H__
