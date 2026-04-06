#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("esc poll/kqueue workflow\n");
}

fbt::esc_poll:entry
{
	poll++;
}

fbt::esc_kqfilter:entry
{
	kqfilter++;
}

fbt::esc_kqdetach:entry
{
	kqdetach++;
}

fbt::esc_kqread:entry
{
	kqread++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (poll == 0 && kqfilter == 0)
		failed = 1;
	printf("poll=%d kqfilter=%d kqread=%d kqdetach=%d\n",
	    poll, kqfilter, kqread, kqdetach);
	exit(failed);
}
