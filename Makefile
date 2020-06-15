PROJECT=substrate-c-tool
SOURCES=lib/BLAKE2/sse/blake2b.c lib/libbase58/base58.c src/*.c
LIBFLAGS=-l
LIBRARY=sodium
CFLAGS=-Wall -fstack-protector -DDEFAULT_CONFIG
BIN=bin
CC=gcc

test:
	$(CC) $(CFLAGS) $(SOURCES) lib/munit/munit.c tests/test.c -o bin/test $(LIBFLAGS) $(LIBRARY) 

example_address:
	$(CC) $(CFLAGS) examples/generate_address.c $(SOURCES) -o $(BIN)/generate_address $(LIBFLAGS) $(LIBRARY)

example_transaction:
	$(CC) $(CFLAGS) examples/transfer_balance.c $(SOURCES) -o $(BIN)/transfer_balance $(LIBFLAGS) $(LIBRARY)

clean:
	rm ./$(BIN)/*

default: test
