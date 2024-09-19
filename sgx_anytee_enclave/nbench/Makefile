#Macros
default: nbench
ACC = aarch64-none-linux-gnu-gcc
CFLAGS = -g -static -O2 -march=armv8-a
DEFINES= -DLINUX $(NO_UNAME)

#Dependencies
sysinfoc.c: Makefile
	./sysinfo.sh $(ACC) $(DEFINES)

sysinfo.c: Makefile
	./sysinfo.sh $(ACC) $(DEFINES)
	

hardware.o: hardware.c hardware.h Makefile
	$(ACC) $(DEFINES) $(CFLAGS)\
		-c hardware.c

nbench0.o: nbench0.h nbench0.c nmglobal.h pointer.h hardware.h\
	   Makefile sysinfo.c sysinfoc.c
	$(ACC) $(DEFINES) $(CFLAGS)\
		-c nbench0.c

emfloat.o: emfloat.h emfloat.c nmglobal.h pointer.h Makefile
	$(ACC) $(DEFINES) $(CFLAGS)\
		-c emfloat.c

pointer.h: pointer Makefile
	aarch64-none-linux-gnu-gcc $(DEFINES) $(CFLAGS)\
		-o pointer pointer.c
	rm -f pointer.h
	echo "#define LONG64" >pointer.h

misc.o: misc.h misc.c Makefile
	$(ACC) $(DEFINES) $(CFLAGS)\
		-c misc.c

nbench1.o: nbench1.h nbench1.c wordcat.h nmglobal.h pointer.h Makefile
	$(ACC) $(DEFINES) $(CFLAGS)\
		-c nbench1.c

sysspec.o: sysspec.h sysspec.c nmglobal.h pointer.h Makefile
	$(ACC) $(DEFINES) $(CFLAGS)\
		-c sysspec.c

contiguousMalloc.o: contiguousMalloc.h cma_malloc.h
	$(ACC) $(DEFINES) $(CFLAGS)\
		-c contiguousMalloc.c

nbench: emfloat.o misc.o nbench0.o nbench1.o sysspec.o hardware.o contiguousMalloc.o
	$(ACC) $(DEFINES) $(CFLAGS) \
		emfloat.o misc.o nbench0.o nbench1.o sysspec.o hardware.o contiguousMalloc.o\
		-o nbench -lm

##########################################################################

clean:
	- /bin/rm -f *.o *~
# * core a.out hello sysinfo.c sysinfoc.c bug pointer pointer.h debugbit.dat

mrproper: clean
	- /bin/rm -f nbench
