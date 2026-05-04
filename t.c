/*
	Thread killing itself PoC example

	This script demostrate how a thread can kill itself and not needing to join it to free!

	Current Limitation: Cannot share new data between threads yet!
*/
#include <fsl.h>

thread t;

public fn thr__test(char *buff)
{
	print(buff), print(" > "), println(FAG);

	//__syscall__(
	//	(long)&((struct sleep_t){10, 0}), 0, 0, 0, 0, 0, _SYS_NANOSLEEP
	//);

	print(buff), print(" > "), println(FAG);
}

int entry()
{
	FAG = str_dup("dick");
	t = create_thread((handler_t)thr__test, FAG, 0);

	thread * p = to_heap(&t, sizeof(thread));

	struct sleep_t tt = { 2, 0 };
	run_thread((thread *)p, 0);
	for(int i = 0; p->running != 0 && i != 10; i++) {
		__syscall__((long)&tt, 0, 0, 0, 0, 0, _SYS_NANOSLEEP);
		memzero(FAG, 100);
		mem_cpy(FAG, "skid", 4);
		//_printf("[%d] Waiting\r", (void *)&i);
	}

	//thread_kill(p);
	println("\nDone          ");
	return 0;
}
