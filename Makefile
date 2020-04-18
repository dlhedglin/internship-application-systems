EXE = ping
CFLAGS = -Wall
CC = gcc

all: $(EXE)

ping: ping.c
	$(CC) $(CFLAGS) ping.c -o ping