#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 30
#endif

BEGIN {
	printf("esc auth timeout workflow\n");
}

fbt::esc_set_auth_deadline:entry
{
	set_deadline++;
}

fbt::esc_event_handle_timeout:entry
{
	handle_timeout++;
}

fbt::esc_auth_group_mark_response:entry
{
	mark_response++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (set_deadline == 0 || handle_timeout == 0)
		failed = 1;
	printf("set_deadline=%d handle_timeout=%d mark_response=%d\n",
	    set_deadline, handle_timeout, mark_response);
	exit(failed);
}
