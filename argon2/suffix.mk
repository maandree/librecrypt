SUPPORT_ANY_ARGON2 = ($(SUPPORT_ARGON2I) || $(SUPPORT_ARGON2D) || $(SUPPORT_ARGON2ID) || $(SUPPORT_ARGON2DS))

HDR += argon2/argon2.h

OBJ_ARGON2 !=\
	if $(SUPPORT_ANY_ARGON2); then echo\
		argon2/hash.o\
		argon2/test_supported.o\
		argon2/is_algorithm.o\
		argon2/make_settings.o\
	;fi

OBJ_PRIVATE += $(OBJ_ARGON2)

OBJ_COMMON_RFC4848S4 = $(USE_OBJ_COMMON_RFC4848S4)

CPPFLAGS_ARGON2 !=\
	if $(SUPPORT_ARGON2I); then echo\
		-DSUPPORT_ARGON2I\
	;fi;\
	if $(SUPPORT_ARGON2D); then echo\
		-DSUPPORT_ARGON2D\
	;fi;\
	if $(SUPPORT_ARGON2ID); then echo\
		-DSUPPORT_ARGON2ID\
	;fi;\
	if $(SUPPORT_ARGON2DS); then echo\
		-DSUPPORT_ARGON2DS\
	;fi

CFLAGS_ARGON2 !=\
	if $(SUPPORT_ANY_ARGON2); then echo\
		-pthread\
	;fi

LDFLAGS_ARGON2 !=\
	if $(SUPPORT_ANY_ARGON2); then echo\
		-lar2simplified\
		-lar2\
		-lblake\
		-pthread\
	;fi

CPPFLAGS_MODULES += $(CPPFLAGS_ARGON2)
CFLAGS_MODULES += $(CFLAGS_ARGON2)
LDFLAGS_MODULES += $(LDFLAGS_ARGON2)


clean: clean-argon2
clean-argon2:
	-rm -f -- argon2/*.o argon2/*.lo argon2/*.su argon2/*.to argon2/*.t
	-rm -f -- argon2/*.gch argon2/*.gcov argon2/*.gcno argon2/*.gcda
