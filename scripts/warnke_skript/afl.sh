#!/usr/bin/bash
cd /src/julea
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
		hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
		name=$(echo "${compiler}-${flags}" | sed "s/ /-/g" | sed "s/--/-/g" | sed "s/--/-/g")
		export CC=${compiler}
		if [ "${asan}" = "asan" ]; then
			export AFL_USE_ASAN=1
			export ASAN_OPTIONS=abort_on_error=1,symbolize=0
			flags="${flags} --debug"
			name="${name}-asan"
		fi
		./waf configure ${flags} --out build-${name} --prefix=prefix-${name} --libdir=prefix-${name} --bindir=prefix-${name} --destdir=prefix-${name} --hdf=${hdf}
		./waf.sh build -j12
		./waf.sh install -j12
		rc=$?; if [[ $rc != 0 ]]; then echo "compile build-${name} failed";exit $rc; fi
		lcov --zerocounters -d "build-${name}"
		mkdir -p afl/cov
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
		programname=$7
		servers="$(hostname)"
		if [ "${servercount}" -eq "0" ]; then
			component="client"
		else
			compiler="afl-gcc"
			component="server"
			i=0
			port=$((10000 + ${index} * 10 + $i))
			servers="$(hostname):${port}"
			for (( i=1; i < ${servercount}; i++ ))
			do
				port=$((10000 + ${index} * 10 + $i))
				servers="${servers},$(hostname):${port}"
			done
		fi
		name=$(echo "${compiler}-${flags}" | sed "s/ /-/g" | sed "s/--/-/g" | sed "s/--/-/g")
		unset AFL_USE_ASAN
		unset ASAN_OPTIONS
		export G_MESSAGES_DEBUG=
		if [ "${asan}" == "asan" ]
		then
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
		export G_SLICE=always-malloc
		export G_DEBUG=gc-friendly,resident-modules
		export AFL_NO_UI=1
		export AFL_NO_AFFINITY=1
		export AFL_SKIP_CRASHES=1
		export JULEA_CONFIG=~/.config/julea/julea${index}
		export GCOV_PREFIX=./afl/cov/fuzzer${index}
		mkdir -p ./afl/cov/fuzzer${index}/src/julea/
		cp -r build-${name} ./afl/cov/fuzzer${index}/src/julea/
		for (( i=0; i < ${servercount}; i++ ))
		do
			mkdir -p ./afl/cov/server${index}-$i/src/julea/
			cp -r build-${name} ./afl/cov/server${index}-$i/src/julea/
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
				export GCOV_PREFIX=./afl/cov/server${index}-$i
				export JULEA_CONFIG=~/.config/julea/julea${index}-$i
				echo ./build-${name}/server/julea-server --port=$((10000 + ${index} * 10 + $i))
				     ./build-${name}/server/julea-server --port=$((10000 + ${index} * 10 + $i)) &
			)
		done
		sleep 2s
		echo "export JULEA_CONFIG=~/.config/julea/julea${index}"
		for a in ./afl/start-files/*.bin; do
			echo "cat $a | ./build-${name}/test-afl/${programname}"
			      cat $a | ./build-${name}/test-afl/${programname}
		done
		if [ "${asan}" != "asan" ]
		then
			#asan not first in library list - first ist afl - all asan tests will fail
			if [ "${servercount}" -gt "0" ]
			then
				#some julea-tests assume that component=server
				(
					./build-${name}/test/julea-test
					rc=$?; if [[ $rc != 0 ]]; then echo "julea-test build-${test_name} failed";exit $rc; fi
				)
			fi
		fi
		afl-fuzz ${aflfuzzflags} fuzzer${index} -i ./afl/start-files -o ./afl/out ./build-${name}/test-afl/${programname}
	)
}
julea_compile "afl-gcc" "--gcov" "" > log/compile1 2>&1
julea_compile "afl-gcc" "--gcov --debug" "" > log/compile2 2>&1
julea_compile "afl-gcc" "" "asan" > log/compile3 2>&1
julea_compile "afl-gcc" "--gcov --testmockup" "" > log/compile4 2>&1
julea_compile "afl-gcc" "--gcov --testmockup --debug" "" > log/compile5 2>&1
julea_compile "afl-clang-fast" "" "" > log/compile6 2>&1
julea_compile "afl-clang-fast" "--debug" "" > log/compile7 2>&1
julea_compile "afl-clang-fast" "--testmockup" "" > log/compile8 2>&1
julea_compile "afl-clang-fast" "--testmockup --debug" "" > log/compile9 2>&1

cp test-afl/bin/* ./afl/start-files/
c=$(ls -la ./afl/start-files/ | wc -l)
if (( $c < 10 )); then
    i=0
    (
		servers="$(hostname):${port}"
		component="client"
		index=$i
		name="afl-clang-fast-debug"
		./build-${name}/tools/julea-config --user \
			--object-servers="${servers}" --object-backend=posix --object-component="${component}" --object-path="/mnt2/julea/object${index}" \
			--kv-servers="${servers}"     --kv-backend=sqlite    --kv-component="${component}"     --kv-path="/mnt2/julea/kv${index}" \
			--smd-servers="${servers}"    --smd-backend=sqlite   --smd-component="${component}"    --smd-path=":memory:"
                eval "mv ~/.config/julea/julea ~/.config/julea/julea${index}"
		export LD_LIBRARY_PATH=prefix-${name}/lib/:$LD_LIBRARY_PATH
		export JULEA_CONFIG=~/.config/julea/julea${i}
		./build-${name}/test-afl/julea-test-afl-smd-backend ./afl
		./build-${name}/test-afl/julea-test-afl-smd-schema ./afl
	)
fi
i=9;
i=$(($i + 1)); julea_run "afl-gcc" "--gcov" "" "$i" "-m none -t 10000 -S" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-gcc" "--gcov --debug" "" "$i" "-m none -t 10000 -S" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-gcc" "" "asan" "$i" "-m none -t 10000 -S" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-gcc" "--gcov --testmockup" "" "$i" "-m none -t 10000 -S" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-gcc" "--gcov --testmockup --debug" "" "$i" "-m none -t 10000 -S" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -M" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-clang-fast" "--debug" "" "$i" "-m none -t 10000 -M" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-clang-fast" "--testmockup" "" "$i" "-m none -t 10000 -M" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-clang-fast" "--testmockup --debug" "" "$i" "-m none -t 10000 -M" "0" "julea-test-afl-smd-backend" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-gcc" "--gcov" "" "$i" "-m none -t 10000 -S" "0" "julea-test-afl-smd-schema" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-gcc" "--gcov --debug" "" "$i" "-m none -t 10000 -S" "0" "julea-test-afl-smd-schema" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-gcc" "" "asan" "$i" "-m none -t 10000 -S" "0" "julea-test-afl-smd-schema" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-clang-fast" "" "" "$i" "-m none -t 10000 -M" "0" "julea-test-afl-smd-schema" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s
i=$(($i + 1)); julea_run "afl-clang-fast" "--debug" "" "$i" "-m none -t 10000 -M" "0" "julea-test-afl-smd-schema" > "log/run$i.out" 2>"log/run$i.err" &
sleep 0.5s


echo "done"
wait
