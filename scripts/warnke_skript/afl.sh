#!/usr/bin/bash
./scripts/warnke_skript/format.sh
rm -rf build afl /mnt2/julea/*
mkdir afl
mkdir afl/cov
sudo echo core >/proc/sys/kernel/core_pattern
sudo echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
export ASAN_OPTIONS=abort_on_error=1,symbolize=0
export AFL_USE_ASAN=1

#CC=afl-gcc ./waf configure --debug --sanitize
#CC=afl-gcc ./waf.sh build
#cp ./build/test-afl/julea-test-afl afl/julea-test-afl
CC=afl-gcc ./waf configure --gcov --debug
CC=afl-gcc ./waf.sh build
cp ./build/test-afl/julea-test-afl afl/julea-test-afl
cp ./build/server/julea-server afl/julea-server

./build/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path="/mnt2/julea/object" \
  --kv-backend=sqlite --kv-component=server --kv-path="/mnt2/julea/kv" \
  --smd-backend=sqlite --smd-component=client --smd-path=":memory:"

cd afl/cov
lcov --zerocounters -d ../..
lcov -c -i -d ../.. -o initial.info
cd ../..
mkdir -p ./afl/cov/server/src/julea/julea/
cp -r build ./afl/cov/server/src/julea/julea/
GCOV_PREFIX=afl/cov/server JULEA_CONFIG=~/.config/julea/julea2 ./afl/julea-server &
mkdir -p ./afl/cov/init/src/julea/julea/
cp -r build ./afl/cov/init/src/julea/julea/
GCOV_PREFIX=afl/cov/init ./afl/julea-test-afl /src/julea/julea/afl

for i in {1..11}
do
	mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
	cp -r build ./afl/cov/fuzzer${i}/src/julea/julea/
	GCOV_PREFIX=afl/cov/fuzzer${i} afl-fuzz -m none -S fuzzer$i -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./afl/julea-test-afl &
done
i=12
mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
cp -r build ./afl/cov/fuzzer${i}/src/julea/julea/
GCOV_PREFIX=afl/cov/fuzzer${i} JULEA_CONFIG=~/.config/julea/julea2 afl-fuzz -m none -M fuzzer$i -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./afl/julea-test-afl

#afl-cov -d /src/julea/julea/afl/out --coverage-cmd "cat AFL_FILE | ./afl/julea-test-afl-gcov; JULEA_CONFIG=~/.config/julea/julea2 cat AFL_FILE | ./afl/julea-test-afl-gcov" --code-dir .
