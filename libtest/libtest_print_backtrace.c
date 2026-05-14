/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__linux__)
# define HAVE_LINE_INFO
#endif


void
libtest_print_backtrace(FILE *fp, const char *prefix, const char *indent, size_t first,
                        const struct backtrace *backtrace, ucontext_t *ucontext)
{
	static _Thread_local int recursion_guard = 0;
	int saved_errno;
        unw_word_t rip;
        unw_cursor_t cursor;
        unw_context_t context;
        Dwarf_Addr ip;
	size_t i;
	unsigned int old_alarm;
#if defined(HAVE_LINE_INFO)
	Dwfl_Callbacks callbacks;
	char *debuginfo_path = NULL;
	Dwfl *dwfl = NULL;
	Dwfl_Line *line = NULL;
	Dwfl_Module *module = NULL;
	int lineno = 0; /* initialised for compiler happiness */
        const char *filename = NULL;
        const char *funcname = NULL;
#endif

	if (recursion_guard)
		return;

	old_alarm = alarm(1u);

	saved_errno = errno;
	recursion_guard = 1;
	libtest_malloc_internal_usage++;

	if (!prefix)
		prefix = indent;
	if (!indent)
		indent = prefix;
	if (!prefix || !indent)
		abort();

	if (backtrace) {
		if (ucontext) {
			abort();
		}
	} else if (ucontext) {
		if (unw_init_local2(&cursor, (unw_context_t *)ucontext, UNW_INIT_SIGNAL_FRAME))
			goto out;
	} else {
		if (unw_getcontext(&context))
			goto out;
		if (unw_init_local(&cursor, &context))
			goto out;
	}

#if defined(__linux__)
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.find_elf        = &dwfl_linux_proc_find_elf;
        callbacks.find_debuginfo  = &dwfl_standard_find_debuginfo;
        callbacks.section_address = NULL;
        callbacks.debuginfo_path  = &debuginfo_path;

	dwfl = dwfl_begin(&callbacks);
	if (dwfl) {
		if (dwfl_linux_proc_report(dwfl, getpid()) ||
		    dwfl_report_end(dwfl, NULL, NULL)) {
			dwfl_end(dwfl);
			dwfl = NULL;
		}
	}
#endif

	for (i = 0u; backtrace ? i < backtrace->n : unw_step(&cursor) > 0; i++) {
		if (backtrace) {
			ip = backtrace->trace[i];
		} else {
			if (unw_get_reg(&cursor, UNW_REG_IP, &rip))
				break;
			ip = (Dwarf_Addr)rip;
		}
		if (i < first)
			continue;

#if defined(HAVE_LINE_INFO)
		if (dwfl) {
			module   = dwfl_addrmodule(dwfl, ip);
			funcname = module ? dwfl_module_addrname(module, ip) : NULL;
			line     = dwfl_getsrc(dwfl, ip);
			if (line) {
				filename = dwfl_lineinfo(line, &(Dwarf_Addr){0}, &lineno, NULL, NULL, NULL);
# ifdef USE_BASENAMES_IN_BACKTRACES
				if (strrchr(filename, '/'))
					filename = &strrchr(filename, '/')[1];
# endif
			}
		}
#endif

#if defined(HAVE_LINE_INFO)
		fprintf(fp, "%s0x%016"PRIxPTR": %s", prefix, (uintptr_t)ip, funcname ? funcname : "???");
		if (line)
			fprintf(fp, " (%s:%i)\n", filename, lineno);
		else
			fprintf(fp, "\n");
#else
		fprintf(fp, "%s0x%016"PRIxPTR"\n", prefix, (uintptr_t)ip);
#endif
		prefix = indent;
	}

#if defined(HAVE_LINE_INFO)
	if (dwfl)
		dwfl_end(dwfl);
#endif

out:
	libtest_malloc_internal_usage--;
	recursion_guard = 0;
	errno = saved_errno;

	alarm(old_alarm);
}


#else


CONST int
main(void)
{
	/* How would one even test this, and what would be the point? */
	return 0;
}


#endif
