#include <stdio.h>

#include "daemon.h"

#include <stdlib.h>

int main() {
	daemon_create();

	net_running(IKE.net);
	while(1);

	return 0;
}
