# makefile for sha-collection

# only tested on: Linux LX 4.19.0-14-amd64 #1 SMP Debian 4.19.171-2 (2021-01-30) x86_64 GNU/Linux)
# g++ version: at least 8.3.0
# c++ std: at least C++??

CC = g++
CFLAGS = -Wall -pedantic -std=c++17 -O3

hashme: main.cpp
	$(CC) -o hashme main.cpp $(CFLAGS)
