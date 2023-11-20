all: aes.exe


aes.exe: main.c
	gcc main.c -o aes.exe

