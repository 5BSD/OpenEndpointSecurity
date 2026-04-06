#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("esc auth dispatch workflow\n");
}

fbt::esc_generate_vnode_event:entry
/((arg0 & 0x1000) == 0)/
{
	auth_gen++;
	self->auth = 1;
}

fbt::esc_pending_alloc:entry
/self->auth/
{
	pending++;
}

fbt::esc_dispatch_event:entry
/self->auth/
{
	dispatch++;
}

fbt::esc_event_enqueue:entry
/self->auth/
{
	enqueue++;
}

fbt::esc_generate_vnode_event:return
/self->auth/
{
	self->auth = 0;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (auth_gen == 0 || pending == 0 || dispatch == 0)
		failed = 1;
	printf("auth_gen=%d pending=%d dispatch=%d enqueue=%d\n",
	    auth_gen, pending, dispatch, enqueue);
	exit(failed);
}
