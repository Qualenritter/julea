#!/usr/bin/bash
cd /src/julea/julea
./scripts/warnke_skript/kill.sh
rm -rf prefix* build* afl
rm -rf /mnt2/julea/* ~/.config/julea/* log
./scripts/warnke_skript/format.sh
mkdir -p afl/start-files log
sudo echo core >/proc/sys/kernel/core_pattern
sudo echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

function julea_compile(){
	(
		compiler=$1
		flags=$2
		asan=$3
		name=$(echo "${compiler}-${flags}" | sed "s/ /-/g" | sed "s/--/-/g" | sed "s/--/-/g")
		export CC=${compiler}
		if [ "${asan}" = "asan" ]; then
			export AFL_USE_ASAN=1
			export ASAN_OPTIONS=abort_on_error=1,symbolize=0
			flags="${flags} --debug"
			name="${name}-asan"
		fi
		./waf configure ${flags} --out "build-${name}" --prefix="prefix-${name}" --libdir="prefix-${name}" --bindir="prefix-${name}" --destdir="prefix-${name}"
		./waf.sh build
		./waf.sh install
		rc=$?; if [[ $rc != 0 ]]; then echo "compile build-${name} failed";exit $rc; fi
		lcov --zerocounters -d "build-${name}"
		lcov -c -i -d "build-${name}" -o "afl/cov/build-${name}.info"
	)
}
function julea_run(){
	(
		compiler=$1
		flags=$2
		asan=$3
		index=$4
		aflfuzzflags=$5
		servercount=$6
		servers="$(hostname)"
		if [ "${servercount}" -eq "0" ]; then
			component="client"
		else
			compiler="afl-gcc"
			component="server"
			i=0
			port=$((10000 + ${index} * 10 + $i))
			servers="$(hostname)@${port}"
			for (( i=1; i < ${servercount}; i++ ))
			do
				port=$((10000 + ${index} * 10 + $i))
				servers="${servers},$(hostname)@${port}"
			done
		fi
		name=$(echo "${compiler}-${flags}" | sed "s/ /-/g" | sed "s/--/-/g" | sed "s/--/-/g")
		if [ "${asan}" = "asan" ]; then
			export AFL_USE_ASAN=1
			export ASAN_OPTIONS=abort_on_error=1,symbolize=0
			name="${name}-asan"
		fi
		echo compiler $compiler
		echo flags $flags
		echo asan $asan
		echo index $index
		echo aflfuzzflags $aflfuzzflags
		echo servercount $servercount
		export LD_LIBRARY_PATH="prefix-${name}/lib/:${LD_LIBRARY_PATH}"
		./build-${name}/tools/julea-config --user \
			--object-servers="${servers}" --object-backend=posix --object-component="${component}" --object-path="/mnt2/julea/object${index}" \
			--kv-servers="${servers}"     --kv-backend=sqlite    --kv-component="${component}"     --kv-path="/mnt2/julea/kv${index}" \
			--smd-servers="${servers}"    --smd-backend=sqlite   --smd-component="${component}"    --smd-path=":memory:"
		eval "mv ~/.config/julea/julea ~/.config/julea/julea${index}"
#		export G_MESSAGES_DEBUG=all
		export G_SLICE=always-malloc
		export G_DEBUG=gc-friendly
		export AFL_NO_UI=1
		export AFL_NO_AFFINITY=1
		export AFL_SKIP_CRASHES=1
		export JULEA_CONFIG=~/.config/julea/julea${index}
		export GCOV_PREFIX=afl/cov/fuzzer${index}
		mkdir -p ./afl/cov/fuzzer${index}/src/julea/julea/
		cp -r build-${name} ./afl/cov/fuzzer${index}/src/julea/julea/
		for (( i=0; i < ${servercount}; i++ ))
		do
			mkdir -p ./afl/cov/server${index}-$i/src/julea/julea/
			cp -r build-${name} ./afl/cov/server${index}-$i/src/julea/julea/
		done
		mkdir -p afl/out
		for (( i=0; i < ${servercount}; i++ ))
		do
			(
				./build-${name}/tools/julea-config --user \
					--object-servers="${servers}" --object-backend=posix --object-component="${component}" --object-path="/mnt2/julea/object${index}-$i" \
					--kv-servers="${servers}"     --kv-backend=sqlite    --kv-component="${component}"     --kv-path="/mnt2/julea/kv${index}-$i" \
					--smd-servers="${servers}"    --smd-backend=sqlite   --smd-component="${component}"    --smd-path=":memory:"
				eval "mv ~/.config/julea/julea ~/.config/julea/julea${index}-$i"
				export GCOV_PREFIX=afl/cov/server${index}-$i
				export JULEA_CONFIG=~/.config/julea/julea${index}-$i
				echo ./build-${name}/server/julea-server --port=$((10000 + ${index} * 10 + $i))
				     ./build-${name}/server/julea-server --port=$((10000 + ${index} * 10 + $i)) &
			)
		done
		sleep 2s
		echo "export JULEA_CONFIG=~/.config/julea/julea${index}"
		for a in {1..40}; do
			echo "cat ./afl/start-files/$a.bin | ./build-${name}/test-afl/julea-test-afl"
			      cat ./afl/start-files/$a.bin | ./build-${name}/test-afl/julea-test-afl
		done
		./build-${name}/test/julea-test
		rc=$?; if [[ $rc != 0 ]]; then echo "julea-test build-${name} failed";exit $rc; fi
		afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-${name}/test-afl/julea-test-afl
#		if [ "${name}" = "afl-clang-fast-" ]; then
#			afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-afl-clang-fast-/test-afl/julea-test-afl
#		elif [ "${name}" = "afl-clang-fast-gcov" ]; then
#			afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-afl-clang-fast-gcov/test-afl/julea-test-afl
#		elif [ "${name}" = "afl-clang-fast-gcov-debug" ]; then
#			afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-afl-clang-fast-gcov-debug/test-afl/julea-test-afl
#		elif [ "${name}" = "afl-gcc-" ]; then
#			afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-afl-gcc-/test-afl/julea-test-afl
#		elif [ "${name}" = "afl-gcc-gcov" ]; then
#			afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-afl-gcc-gcov/test-afl/julea-test-afl
#		elif [ "${name}" = "afl-gcc-gcov-debug" ]; then
#			afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-afl-gcc-gcov-debug/test-afl/julea-test-afl
#		elif [ "${name}" = "afl-gcc-gcov-asan" ]; then
#			afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-afl-gcc-gcov-asan/test-afl/julea-test-afl
#		fi
	)
}
julea_compile "afl-gcc" "" "" > log/compile1 2>&1
julea_compile "afl-gcc" "--gcov" "" > log/compile2 2>&1
julea_compile "afl-gcc" "--gcov --debug" "" > log/compile3 2>&1
julea_compile "afl-gcc" "--gcov" "asan" > log/compile4 2>&1
julea_compile "afl-clang-fast" "" "" > log/compile5 2>&1
julea_compile "afl-clang-fast" "--gcov" "" > log/compile6 2>&1
julea_compile "afl-clang-fast" "--gcov --debug" "" > log/compile7 2>&1

cp test-afl/bin/* ./afl/start-files/
c=$(ls -la ./afl/start-files/ | wc -l)
if (( $c < 10 )); then
    i=0
    (
		name="afl-gcc-gcov-debug"
		export LD_LIBRARY_PATH=prefix-${name}/lib/:$LD_LIBRARY_PATH
		export JULEA_CONFIG=~/.config/julea/julea${i}
		./build-${name}/test-afl/julea-test-afl ./afl/start-files/
	)
fi

i=10; julea_run "afl-gcc" "--gcov --debug" "" "$i" "-m none -t 10000 -M" "0" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=11; julea_run "afl-gcc" "--gcov" "" "$i" "-m none -t 10000 -S" "0" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=12; julea_run "afl-gcc" "--gcov" "" "$i" "-m none -t 10000 -S" "1" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=13; julea_run "afl-gcc" "--gcov" "" "$i" "-m none -t 10000 -S" "2" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=14; julea_run "afl-gcc" "--gcov --debug" "" "$i" "-m none -t 10000 -S" "0" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=15; julea_run "afl-gcc" "--gcov --debug" "" "$i" "-m none -t 10000 -S" "1" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=16; julea_run "afl-gcc" "--gcov --debug" "" "$i" "-m none -t 10000 -S" "2" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=17; julea_run "afl-gcc" "--gcov" "asan" "$i" "-m none -t 10000 -S" "0" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=18; julea_run "afl-gcc" "--gcov" "asan" "$i" "-m none -t 10000 -M" "1" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=19; julea_run "afl-gcc" "--gcov" "asan" "$i" "-m none -t 10000 -S" "2" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=20; julea_run "afl-gcc" "--gcov" "asan" "$i" "-m none -t 10000 -S" "3" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=21; julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -S" "0" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=22; julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -M" "1" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=23; julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -S" "2" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=24; julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -S" "3" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=25; julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -S" "0" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=26; julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -S" "1" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=27; julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -M" "2" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=28; julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -S" "3" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=29; julea_run "afl-clang-fast" "--gcov" "" "$i" "-m none -t 10000 -S" "0" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=30; julea_run "afl-clang-fast" "--gcov" "" "$i" "-m none -t 10000 -S" "1" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=31; julea_run "afl-clang-fast" "--gcov" "" "$i" "-m none -t 10000 -S" "2" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=32; julea_run "afl-clang-fast" "--gcov" "" "$i" "-m none -t 10000 -S" "3" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=33; julea_run "afl-clang-fast" "--gcov --debug" "" "$i" "-m none -t 10000 -M" "0" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=34; julea_run "afl-clang-fast" "--gcov --debug" "" "$i" "-m none -t 10000 -S" "1" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=35; julea_run "afl-clang-fast" "--gcov --debug" "" "$i" "-m none -t 10000 -S" "2" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=36; julea_run "afl-clang-fast" "--gcov --debug" "" "$i" "-m none -t 10000 -S" "3" > "log/run$i.out" 2>"log/run$i.err" &

echo "done"
wait
