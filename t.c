/*
	Thread killing itself PoC example

	This script demostrate how a thread can kill itself and not needing to join it to free!

	Current Limitation: Cannot share new data between threads yet!
*/
#include <fsl.h>

thread t;

public fn thr__test(thread *arg)
{
	print("Running Status: "), printi(arg->running), println(NULL);
	struct sleep_t tt = { 5, 0 };
	__syscall__((long)&tt, 0, 0, 0, 0, 0, _SYS_NANOSLEEP);

	arg->running = 0;
	thread_kill(arg);
	println("Exiting thread...");
}

int entry()
{
	t = create_thread((handler_t)thr__test, NULL, 0);

	thread * p = allocate(0, sizeof(thread));
	mem_cpy(p, &t, sizeof(thread));

	p->arguments = p;

	struct sleep_t tt = { 1, 0 };
	run_thread((thread *)p, 0);
	for(int i = 0; p->running != 0 && i != 10; i++) {
		__syscall__((long)&tt, 0, 0, 0, 0, 0, _SYS_NANOSLEEP);
		print("Waiting\r");
	}

	//thread_kill(p);
	println(NULL);
	println("Done          ");
	return 0;
}
