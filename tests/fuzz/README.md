Run fuzz tests.

# Quickstart

*Requires that the project is already configured*

* Install `american-fuzz-lop` in host (for instance from your distro's package manager)
* run `make run_scale` to test SCALE
* run `make run_extrinsic` to test Extrinsic (transaction) encoded and decoder

# Analysis of the results
The program generates report in the `out` folder. If there are cases that crash the program, they
are stored in the `out/crashes` folder (otherwise it's empty).
To see what input caused the crash, you can run the program with that input.
For instance, in the case of SCALE, you run:
``./bin/fuzzScale ./out/crashes/[NAME_OF_THE_FILE]``
