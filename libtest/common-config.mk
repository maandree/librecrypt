C17 !=\
	if command -v c17 >/dev/null || ! command -v cc >/dev/null; then\
		echo c17;\
	else\
		echo cc -std=c17;\
	fi

IMPLEMENT_MMAP_CPPFLAGS !=\
	if $(IMPLEMENT_MMAP); then\
		echo -DIMPLEMENT_MMAP;\
	fi

OBJ_MMAP !=\
	if $(IMPLEMENT_MMAP); then\
		echo mmap.o;\
	fi
