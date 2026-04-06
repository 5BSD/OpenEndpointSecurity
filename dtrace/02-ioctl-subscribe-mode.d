#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("esc ioctl subscribe/mode workflow\n");
}

fbt::esc_ioctl_subscribe:entry
{
	subscribe++;
	self->sub = 1;
}

fbt::esc_client_subscribe_events:entry
/self->sub/
{
	subscribe_events++;
}

fbt::esc_ioctl_subscribe:return
/self->sub/
{
	self->sub = 0;
}

fbt::esc_ioctl_set_mode:entry
{
	set_mode++;
}

fbt::esc_client_set_mode:entry
{
	client_set_mode++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (subscribe == 0 || subscribe_events == 0)
		failed = 1;
	printf("subscribe=%d subscribe_events=%d set_mode=%d client_set_mode=%d\n",
	    subscribe, subscribe_events, set_mode, client_set_mode);
	exit(failed);
}
