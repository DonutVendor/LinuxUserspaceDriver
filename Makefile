main: userspaceDriver.o
	gcc -o userspaceDriver userspaceDriver.o
main.o: userspaceDriver.c
	gcc -c userspaceDriver.c