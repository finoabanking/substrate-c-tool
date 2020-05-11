ifeq ($(DEFAULT_CONFIG),1)
	CFLAGS=-DDEFAULT_CONFIG
endif

scale:
	afl-g++ -x c -c ../../src/scale.c $(CFLAGS) -o ./bin/scale.o
	afl-g++ -c fuzzScale.cpp -o bin/fuzzScale.o
	afl-g++ -o ./bin/fuzzScale ./bin/fuzzScale.o ./bin/scale.o

extrinsic:
	afl-gcc -c ../../src/scale.c $(CFLAGS) -o ./bin/scale.o
	afl-gcc -c ../../src/kusama.c $(CFLAGS) -o ./bin/kusama.o
	afl-gcc -c ../../src/transactions.c $(CFLAGS) -o ./bin/transactions.o
	afl-gcc -c ../../src/extrinsic.c $(CFLAGS) -o ./bin/extrinsic.o
	afl-g++ -c fuzzExtrinsic.cpp $(CFLAGS) -o bin/fuzzExtrinsic.o
	afl-g++ -l sodium -o ./bin/fuzzExtrinsic ./bin/fuzzExtrinsic.o ./bin/kusama.o ./bin/transactions.o ./bin/extrinsic.o ./bin/scale.o

run_scale: scale
	AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 afl-fuzz -i ./in -o ./out ./bin/fuzzScale

run_extrinsic: extrinsic
	AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 afl-fuzz -i ./in_extrinsic -o ./out_extrinsic ./bin/fuzzExtrinsic

clean:
	rm ./bin/*
