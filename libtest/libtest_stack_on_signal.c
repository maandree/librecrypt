/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST

# ifdef WITH_BACKTRACE


static void
stack_dumper(int sig, siginfo_t *info, void *ucontext)
{
	(void) sig;
	(void) info;
	libtest_print_backtrace(stderr, "crashed at ", "        by ", 0u, NULL, ucontext);
}


static stack_t ss;
static size_t have_ss = 0u;


static void
create_altstack(void)
{
	if (have_ss++)
		return;
	ss.ss_sp = libtest_real_mmap(NULL, (size_t)SIGSTKSZ, PROT_READ | PROT_WRITE,
	                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(ss.ss_sp != MAP_FAILED);
	ss.ss_size = (size_t)SIGSTKSZ;
	ss.ss_flags = 0;
	assert(!sigaltstack(&ss, NULL));
}


static void
destroy_altstack(void)
{
	if (--have_ss)
		return;
	assert(!libtest_real_munmap(ss.ss_sp, ss.ss_size));
}


void
libtest_stack_on_signal(int signo, struct sigaction *old_out)
{
	struct sigaction sa;

	create_altstack();

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = &stack_dumper;
	sa.sa_flags = (int)(SA_RESETHAND | SA_SIGINFO);
	if (have_ss)
		sa.sa_flags |= SA_ONSTACK;
	sigfillset(&sa.sa_mask);

	assert(!sigaction(signo, &sa, old_out));
}


void
libtest_stop_stack_on_signal(int signo, const struct sigaction *old)
{
	assert(!sigaction(signo, old, NULL));
	destroy_altstack();
}


#else


void
libtest_stack_on_signal(int signo, struct sigaction *old_out)
{
	(void) signo;
	(void) old_out;
}

void
libtest_stop_stack_on_signal(int signo, const struct sigaction *old)
{
	(void) signo;
	(void) old;
}


# endif


#else


CONST int
main(void)
{
	/* How would one even test this, and what would be the point? */
	return 0;
}


#endif
