# P-256 receiver computation order

This standalone variant of the isolation experiment compares two schedules for the same receiver computation. The default (0) performs the choice-indexed lookups before the nonce multiplication. Order 1 performs the nonce multiplication first. Both orders use the same fastest-line decoder. The two programs share a memory object specific to this variant.

## Build and run on x86-64 Linux

Run these commands inside this directory. Start a fresh honest process for each run.

```sh
gcc -O2 -march=native beaver_honest.c -o beaver_honest -lrt
gcc -O2 -march=native beaver_attacker.c -o beaver_attacker -lrt
./beaver_honest &
BEAVER_HEADER=1 BEAVER_EC_ORDER=0 ./beaver_attacker 200 20
wait
./beaver_honest &
BEAVER_HEADER=1 BEAVER_EC_ORDER=1 ./beaver_attacker 200 20
wait
```

The arguments are trial count and AES vote count. Each EC choice is probed once. The output includes the selected order, exact choice-byte recovery, and XOR input recovery. The paper's cycle and nibble diagnostics come from a separately instrumented harness.
