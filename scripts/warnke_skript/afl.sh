./scripts/warnke_skript/format.sh
rm -rf build afl
CC=afl-gcc ./waf configure --debug
./waf.sh build
export ASAN_OPTIONS=abort_on_error=1,symbolize=0
sudo echo core >/proc/sys/kernel/core_pattern
sudo echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
./build/test-afl/julea-test-afl /src/julea/julea/afl
afl-fuzz -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build/test-afl/julea-test-afl


