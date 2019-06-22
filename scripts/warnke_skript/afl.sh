#!/usr/bin/bash
./scripts/warnke_skript/format.sh
rm -rf build afl /mnt2/julea/*
mkdir afl
sudo echo core >/proc/sys/kernel/core_pattern
sudo echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
export ASAN_OPTIONS=abort_on_error=1,symbolize=0
export AFL_USE_ASAN=1

CC=afl-gcc ./waf configure --debug --sanitize
CC=afl-gcc ./waf.sh build
cp ./build/test-afl/julea-test-afl afl/julea-test-afl
CC=afl-gcc ./waf configure --gcov
CC=afl-gcc ./waf.sh build
cp ./build/test-afl/julea-test-afl afl/julea-test-afl-gcov


# server MUST NOT run the smd backend
./build/server/julea-server &

./afl/julea-test-afl /src/julea/julea/afl


afl-cov -d /src/julea/julea/afl/out --live --coverage-cmd "cat AFL_FILE | ./afl/julea-test-afl-gcov" --code-dir . &

for i in {1..10}
do
./build/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path="/mnt2/julea/object" \
  --kv-backend=sqlite --kv-component=server --kv-path="/mnt2/julea/kv" \
  --smd-backend=sqlite --smd-component=client --smd-path=":memory:"

afl-fuzz -m none -S fuzzer$i -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./afl/julea-test-afl &

sleep 3

done
i=11
./build/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path="/mnt2/julea/object" \
  --kv-backend=sqlite --kv-component=server --kv-path="/mnt2/julea/kv" \
  --smd-backend=sqlite --smd-component=client --smd-path=":memory:"

afl-fuzz -m none -M fuzzer$i -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./afl/julea-test-afl

