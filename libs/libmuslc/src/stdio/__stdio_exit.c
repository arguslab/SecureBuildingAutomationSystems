/* @LICENSE(MUSLC_MIT) */

#include "stdio_impl.h"

static FILE *const dummy_file = 0;
weak_alias(dummy_file, __stdin_used);
weak_alias(dummy_file, __stdout_used);
weak_alias(dummy_file, __stderr_used);

static void close_file(FILE *f)
{
	if (!f) return;
	FLOCK(f);
	if (f->wpos > f->wbase) f->write(f, 0, 0);
	if (f->rpos < f->rend) f->seek(f, f->rpos-f->rend, SEEK_CUR);
}

void __stdio_exit(void)
{
	FILE *f;
	OFLLOCK();
	for (f=libc.ofl_head; f; f=f->next) close_file(f);
	close_file(__stdin_used);
	close_file(__stdout_used);
}
