/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


struct fd {
	int name;
	int leakable;
};

static size_t nopened = 0u;
static struct fd *opened = NULL;


static int
cmp_fd(const void *av, const void *bv)
{
	const struct fd *a = av;
	const struct fd *b = bv;
	return a->name - b->name;
}


static char *
get_path(int fd)
{
	char path[sizeof("/dev/fd/-") + 3u * sizeof(int)];
	int pathlen;
	char *ret = NULL;
	size_t size = 0;
	ssize_t r;

	pathlen = sprintf(path, "/dev/fd/%i", fd);
	assert(pathlen > (int)sizeof("/dev/fd/") - 1);
	assert((size_t)pathlen < sizeof(path));

	do {
		ret = realloc(ret, size += 128u);
		assert(ret);
		r = readlink(path, ret, size - 1u);
		assert(r >= 0);
		if (r < 0)
			return NULL;
	} while ((size_t)r >= size - 2u);

	ret[r] = '\0';
	return ret;

}


int
libtest_fd_tracking(int action)
{
	size_t new_nopened = 0u;
	struct fd *new_opened = NULL;
	DIR *dir;
	struct dirent *f;
	int ret = 1, dfd, name, digit;
	int accept_memleak = libtest_malloc_accept_leakage;
	size_t i, j;
	char *path;

	/* so libtest doesn't complain about us not zeroing before freeing,
	 * and so it will not report memory leaks in fprintf from our
	 * resource leak report */
	libtest_malloc_accept_leakage = 1;

	dir = opendir("/dev/fd/");
	assert(dir != NULL);
	dfd = dirfd(dir);
next:
	while ((f = readdir(dir))) {
		name = 0;
		for (i = 0u; f->d_name[i]; i++) {
			if ('0' > f->d_name[i] || f->d_name[i] > '9')
				goto next;
			digit = (int)f->d_name[i] - (int)'0';
			if (name > (INT_MAX - digit) / 10)
				goto next;
			name = name * 10 + digit;
		}
		if (name == dfd)
			continue;

		new_opened = realloc(new_opened, (new_nopened + 1u) * sizeof(*new_opened));
		new_opened[new_nopened].name = name;
		new_opened[new_nopened].leakable = action;
		new_nopened += 1u;
	}
	closedir(dir);

	qsort(new_opened, new_nopened, sizeof(*new_opened), &cmp_fd);

	for (i = j = 0u; i < new_nopened || j < nopened;) {
		if (i == new_nopened) {
		old_unique:
			/* the file has been closed, that's great! */
			j++;
		} else if (j == nopened) {
		new_unique:
			if (action < 0) {
				ret = 0;
				path = get_path(new_opened[i].name);
				if (path)
					fprintf(stderr, "File descriptor leak: %i (%s)\n", new_opened[i].name, path);
				else
					fprintf(stderr, "File descriptor leak: %i\n", new_opened[i].name);
				free(path);
			}
			i++;
		} else if (new_opened[i].name < opened[j].name) {
			goto new_unique;
		} else if (new_opened[i].name > opened[j].name) {
			goto old_unique;
		} else {
			new_opened[i].leakable = opened[j].leakable;
			i++;
			j++;
		}
	}

	if (new_nopened == 0u || action < 0) {
		free(new_opened);
		new_opened = NULL;
		new_nopened = 0u;
	}

	if (action >= 0) {
		opened = new_opened;
		nopened = new_nopened;
	} else {
		free(opened);
		opened = NULL;
		nopened = 0u;
	}

	libtest_malloc_accept_leakage = accept_memleak;
	return ret;
}


#else


int
main(void)
{
	SET_UP_ALARM();

	return 0;
}


#endif
/* TODO maybe test */
/* TODO maybe attempt to tracking where files are opened */
