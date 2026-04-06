#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("esc path mute evaluation\n");
}

fbt::esc_event_is_path_muted:entry
{
	check++;
}

fbt::esc_event_path_muted_join:entry
{
	join++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (check == 0)
		failed = 1;
	printf("check=%d join=%d\n", check, join);
	exit(failed);
}
