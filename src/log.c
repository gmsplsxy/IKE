#include "log.h"
#include "daemon.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

log_t* log_create()
{
	log_t* log = calloc(1, sizeof(log_t));
	log->level = ALL;

	return log;
}

void log_free(log_t* log)
{
	free(log);
}

void logging(log_level_t lev, const char* fmt, ...)
{
	if(IKE.log->level <= lev) {
		va_list args;
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
	}
}
