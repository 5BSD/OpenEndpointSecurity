#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("esc rename workflow\n");
}

fbt::esc_rename_cache_store:entry
{
	store++;
}

fbt::esc_rename_cache_take:entry
{
	take++;
}

fbt::esc_generate_vnode_event:entry
/(arg0 == 0x0005)/
{
	rename_auth++;
}

fbt::esc_generate_vnode_event:entry
/(arg0 == 0x1008)/
{
	rename_notify++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (store == 0 || take == 0)
		failed = 1;
	printf("store=%d take=%d rename_auth=%d rename_notify=%d\n",
	    store, take, rename_auth, rename_notify);
	exit(failed);
}
