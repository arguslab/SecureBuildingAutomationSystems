/* @LICENSE(MUSLC_MIT) */

struct __DIR_s
{
	int fd;
	off_t tell;
	int buf_pos;
	int buf_end;
	int lock[2];
	char buf[2048];
};
