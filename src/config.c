#include "config.h"
#include "log.h"

#include <stdlib.h>

void _parsing(configure_t* cfg, const char* filename)
{
	config_t cf;
	config_setting_t *left, *right;
	const char* buf;

	config_init(&cf);

	if(!config_read_file(&cf, filename)) {
		logging(ERR, "[CFG] Failure init config(%s:%d - %s)\n", config_error_file(&cf), config_error_line(&cf), config_error_text(&cf));
		config_destroy(&cf);
		return;
	}

	left = config_lookup(&cf, "left");
	if(left != NULL) {
		if(config_setting_lookup_string(left, "ip", &buf))
			cfg->left.addr = net_stoa(buf);
	}

	right = config_lookup(&cf, "right");
	if(right != NULL) {
		if(config_setting_lookup_string(right, "ip", &buf))
			cfg->right.addr = net_stoa(buf);
	}
}

configure_t* cfg_create(const char* filename)
{
	configure_t* cfg = calloc(1, sizeof(configure_t));

	_parsing(cfg, filename);

	return cfg;
}
