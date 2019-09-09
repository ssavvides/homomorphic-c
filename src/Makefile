CC = gcc
CFLAGS = -g -I/usr/include -Wall -pedantic -Wno-unused-function \
	-Wno-deprecated-declarations -std=gnu11
LDFLAGS= -lssl -lcrypto -lgmp
DEPS = time.h pk.h
OBJ = 	gmp-utils.o \
		bigd.o bigdRand.o bigdigits.o bigdigitsRand.o \
		aes.o aes-ssl.o \
		elgamal-bd.o elgamal-bn.o elgamal-gmp.o \
		paillier-bd.o paillier-bn.o paillier-gmp.o

default: testCrypto timeCrypto

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

testCrypto: testCrypto.o $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

timeCrypto: timeCrypto.o time.o $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -f *.o testCrypto