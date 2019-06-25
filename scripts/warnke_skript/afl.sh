#!/usr/bin/bash
cd /src/julea/julea
#printenv > a
#. ./scripts/environment.sh
#printenv > b
export PKG_CONFIG_PATH=$(echo $PKG_CONFIG_PATH | sed "s_/pkg-config:__g" | sed -e 's_$_/pkg-config_g')
#echo $PKG_CONFIG_PATH
./scripts/warnke_skript/format.sh
./scripts/warnke_skript/kill.sh
rm -rf prefix* build* afl /mnt2/julea/* ~/.config/julea/*
mkdir afl
mkdir afl/out
mkdir afl/cov
mkdir afl/start-files
sudo echo core >/proc/sys/kernel/core_pattern
sudo echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

(export CC=afl-gcc; ./waf configure --gcov --out build-gcc-gcov --prefix=prefix-gcc-gcov --libdir=prefix-gcc-gcov --bindir=prefix-gcc-gcov --destdir=prefix-gcc-gcov && ./waf.sh build && ./waf.sh install)
rc=$?; if [[ $rc != 0 ]]; then echo "build-gcc-gcov failed";exit $rc; fi
lcov --zerocounters -d build-gcc-gcov && lcov -c -i -d build-gcc-gcov -o afl/cov/build-gcc-gcov.info
(export AFL_USE_ASAN=1; export ASAN_OPTIONS=abort_on_error=1,symbolize=0; export CC=afl-gcc; ./waf configure --gcov --debug --out build-gcc-gcov-debug-asan --prefix=prefix-gcc-gcov-debug-asan --libdir=prefix-gcc-gcov-debug-asan --bindir=prefix-gcc-gcov-debug-asan --destdir=prefix-gcc-gcov-debug-asan&& ./waf.sh build && ./waf.sh install)
rc=$?; if [[ $rc != 0 ]]; then echo "build-gcc-gcov-debug-asan failed";exit $rc; fi
lcov --zerocounters -d build-gcc-gcov-debug-asan && lcov -c -i -d build-gcc-gcov-debug-asan -o afl/cov/build-gcc-gcov-debug-asan.info
#(export CC=afl-clang-fast; ./waf configure --gcov --out build-clang-gcov --prefix=prefix-clang-gcov --libdir=prefix-clang-gcov --bindir=prefix-clang-gcov --destdir=prefix-clang-gcov && ./waf.sh build && ./waf.sh install)
#rc=$?; if [[ $rc != 0 ]]; then echo "build-clang-gcov failed";exit $rc; fi
#lcov --zerocounters -d build-clang-gcov && lcov -c -i -d build-clang-gcov -o afl/cov/build-clang-gcov.info
#(export CC=afl-clang-fast; ./waf configure --gcov --debug --out build-clang-gcov-debug --prefix=prefix-clang-gcov-debug --libdir=prefix-clang-gcov-debug --bindir=prefix-clang-gcov-debug --destdir=prefix-clang-gcov-debug && ./waf.sh build && ./waf.sh install)
#rc=$?; if [[ $rc != 0 ]]; then echo "build-clang-gcov-debug failed";exit $rc; fi
#lcov --zerocounters -d build-clang-gcov-debug && lcov -c -i -d build-clang-gcov-debug -o afl/cov/build-clang-gcov-debug.info
(export CC=afl-clang-fast; ./waf configure --out build-clang --prefix=prefix-clang --libdir=prefix-clang --bindir=prefix-clang --destdir=prefix-clang && ./waf.sh build && ./waf.sh install)
rc=$?; if [[ $rc != 0 ]]; then echo "build-clang failed";exit $rc; fi

i=0
(export LD_LIBRARY_PATH=prefix-clang/lib/:$LD_LIBRARY_PATH; ./build-clang/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=client --object-path="/mnt2/julea/object${i}" \
  --kv-backend=sqlite --kv-component=client --kv-path="/mnt2/julea/kv${i}" \
  --smd-backend=sqlite --smd-component=server --smd-path=":memory:")
mv ~/.config/julea/julea ~/.config/julea/julea${i}
for i in {1..24}
do
(export LD_LIBRARY_PATH=prefix-clang/lib/:$LD_LIBRARY_PATH; ./build-clang/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=client --object-path="/mnt2/julea/object${i}" \
  --kv-backend=sqlite --kv-component=client --kv-path="/mnt2/julea/kv${i}" \
  --smd-backend=sqlite --smd-component=client --smd-path=":memory:")
mv ~/.config/julea/julea ~/.config/julea/julea${i}
done

#for coverage clear all counters

#create start files
cp test-afl/bin/* /src/julea/julea/afl/start-files/
c=$(ls -la /src/julea/julea/afl/start-files/ | wc -l)
if (( $c < 10 )); then
	i=1
	mkdir -p ./afl/cov/init/src/julea/julea/
	cp -r build-gcc-gcov ./afl/cov/init/src/julea/julea/
	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1;export LD_LIBRARY_PATH=prefix-gcc-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/init; export JULEA_CONFIG=~/.config/julea/julea${i}; ./build-gcc-gcov/test-afl/julea-test-afl /src/julea/julea/afl)
fi

starting fuzzers M-Mode clang - using julea-server
for i in 0
do
	mkdir -p ./afl/cov/server${i}/src/julea/julea/
	cp -r build-gcc-gcov ./afl/cov/server${i}/src/julea/julea/
	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1;export LD_LIBRARY_PATH=prefix-gcc-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/server${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; ./build-gcc-gcov/server/julea-server) &
	mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
	cp -r build-gcc-gcov ./afl/cov/fuzzer${i}/src/julea/julea/
	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1;export LD_LIBRARY_PATH=prefix-gcc-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-fuzz -m none -t 100000 -M fuzzer${i} -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build-gcc-gcov/test-afl/julea-test-afl) &
#	sleep 2
done
#starting fuzzers M-Mode gcc
for i in 1
do
	mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
	cp -r build-gcc-gcov ./afl/cov/fuzzer${i}/src/julea/julea/
	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1;export LD_LIBRARY_PATH=prefix-gcc-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; ./build-gcc-gcov/test/julea-test) &
	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1;export LD_LIBRARY_PATH=prefix-gcc-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-fuzz -m none -t 100000 -M fuzzer${i} -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build-gcc-gcov/test-afl/julea-test-afl) &
#	sleep 2
done
#starting fuzzers S-Mode
for i in {2..10}
do
	mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
	cp -r build-gcc-gcov ./afl/cov/fuzzer${i}/src/julea/julea/
	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1;export LD_LIBRARY_PATH=prefix-gcc-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-fuzz -m none -t 100000 -S fuzzer${i} -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build-gcc-gcov/test-afl/julea-test-afl) &
#	sleep 2
done
for i in 11
do
	mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
	cp -r build-gcc-gcov-debug-asan ./afl/cov/fuzzer${i}/src/julea/julea/
	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1;export LD_LIBRARY_PATH=prefix-gcc-gcov-debug-asan/lib/:$LD_LIBRARY_PATH; export AFL_USE_ASAN=1; export ASAN_OPTIONS=abort_on_error=1,symbolize=0; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-fuzz -m none -t 100000 -S fuzzer${i} -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build-gcc-gcov-debug-asan/test-afl/julea-test-afl) &
#	sleep 2
done
for i in {12..24}
do
	mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
	cp -r build-clang ./afl/cov/fuzzer${i}/src/julea/julea/
	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1; export LD_LIBRARY_PATH=prefix-clang/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-fuzz -m none -t 100000 -S fuzzer${i} -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build-clang/test-afl/julea-test-afl) &
#	sleep 2
done
#for i in {16..22}
#do
#	mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
#	cp -r build-clang-gcov ./afl/cov/fuzzer${i}/src/julea/julea/
#	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1; export LD_LIBRARY_PATH=prefix-clang-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-fuzz -m none -t 100000 -S fuzzer${i} -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build-clang-gcov/test-afl/julea-test-afl) &
#	sleep 2
#done
#for i in {23..24}
#do
#	mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
#	cp -r build-clang-gcov-debug ./afl/cov/fuzzer${i}/src/julea/julea/
#	(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1; export LD_LIBRARY_PATH=prefix-clang-gcov-debug/lib/:$LD_LIBRARY_PATH; export AFL_USE_ASAN=1; export ASAN_OPTIONS=abort_on_error=1,symbolize=0; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-fuzz -m none -t 100000 -S fuzzer${i} -i /src/julea/julea/afl/start-files -o /src/julea/julea/afl/out ./build-clang-gcov-debug/test-afl/julea-test-afl) &
#	sleep 2
#done
#starting single fuzzer in Coverage-Mode gcc - not working if clang uses same source folder
#i=23
#mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
#cp -r build-gcc-gcov ./afl/cov/fuzzer${i}/src/julea/julea/
#(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1; export LD_LIBRARY_PATH=prefix-gcc-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-cov --live -d /src/julea/julea/afl/out --coverage-cmd "cat AFL_FILE | ./build-gcc-gcov/test-afl/julea-test-afl" --code-dir . )
#i=23
#mkdir -p ./afl/cov/fuzzer${i}/src/julea/julea/
#cp -r build-clang-gcov ./afl/cov/fuzzer${i}/src/julea/julea/
#(export AFL_NO_UI=1; export AFL_NO_AFFINITY=1; export LD_LIBRARY_PATH=prefix-clang-gcov/lib/:$LD_LIBRARY_PATH; export GCOV_PREFIX=afl/cov/fuzzer${i}; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_SKIP_CRASHES=1; afl-cov --live -d /src/julea/julea/afl/out --coverage-cmd "cat AFL_FILE | ./build-clang-gcov/test-afl/julea-test-afl" --code-dir . )




