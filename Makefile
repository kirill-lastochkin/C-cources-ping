OBJ = main.o inf.o ping.o
pi : $(OBJ)
	cc -o pi $(OBJ)
main.o : service.h
inf.o : service.h
ping.o : service.h
clean :
	-rm pi $(OBJ)
cm : 
	cc -o pi main.c inf.c ping.c

