#!/usr/bin/bash
./scripts/warnke_skript/format.sh
rm -rf build afl /mnt2/julea/*
CC=afl-gcc ./waf configure --debug
./waf.sh build
export ASAN_OPTIONS=abort_on_error=1,symbolize=0
sudo echo core >/proc/sys/kernel/core_pattern
sudo echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
./build/test-afl/julea-test-afl /src/julea/julea/afl

# server MUST NOT run the smd backend
./build/server/julea-server &

for i in {1..11}
do
./build/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path="/mnt2/julea/object" \
  --kv-backend=sqlite --kv-component=server --kv-path="/mnt2/julea/kv" \
  --smd-backend=sqlite --smd-component=client --smd-path="/mnt2/julea/smd${i}"

afl-fuzz -S fuzzer$i -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build/test-afl/julea-test-afl &

sleep 3

done
i=12
./build/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path="/mnt2/julea/object" \
  --kv-backend=sqlite --kv-component=server --kv-path="/mnt2/julea/kv" \
  --smd-backend=sqlite --smd-component=client --smd-path="/mnt2/julea/smd${i}"

afl-fuzz -M fuzzer$i -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build/test-afl/julea-test-afl

