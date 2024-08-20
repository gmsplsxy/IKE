#include "daemon.h"

daemon_t IKE;

void daemon_create()
{
	IKE.log = log_create();
	IKE.cfg = cfg_create("conf/sample.conf");
	IKE.net = net_create();
}
