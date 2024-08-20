#ifndef __LOG_H__
#define __LOG_H__

typedef enum {
  ALL = 0,
  DBG,
  INF,
  WAR,
  ERR
}log_level_t;

typedef struct {
  log_level_t level;
}log_t;

log_t*  log_create();
void    log_free(log_t* log);

void    logging(log_level_t lev, const char* fmt, ...);

#endif //__LOG_H__
