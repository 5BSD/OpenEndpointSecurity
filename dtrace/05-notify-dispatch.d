#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("esc notify dispatch workflow\n");
}

fbt::esc_generate_vnode_event:entry
/((arg0 & 0x1000) != 0)/
{
	notify_gen++;
	self->notify = 1;
}

fbt::esc_dispatch_event:entry
/self->notify/
{
	dispatch++;
}

fbt::esc_event_enqueue:entry
/self->notify/
{
	enqueue++;
}

fbt::esc_generate_vnode_event:return
/self->notify/
{
	self->notify = 0;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (notify_gen == 0 || dispatch == 0)
		failed = 1;
	printf("notify_gen=%d dispatch=%d enqueue=%d\n",
	    notify_gen, dispatch, enqueue);
	exit(failed);
}
