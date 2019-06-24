files=$(ls afl/start-files/* | grep -v README )
files="${files} $(ls afl/out/*/crashes/* | grep -v README )"
rm -rf b
mkdir b
export LD_LIBRARY_PATH=prefix-gcc-gcov/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=~/.config/julea/julea1
export AFL_USE_ASAN=1
export ASAN_OPTIONS=abort_on_error=1,symbolize=0
for g in build-clang-gcov-debug build-clang-gcov build-clang build-gcc-gcov build-gcc-gcov-debug-asan
do
mkdir b/${g}
for f in ${files}
do
	cat $f | ./${g}/test-afl/julea-test-afl > /dev/null 2>&1
	r=$?
	if [ $r -eq 0 ]; then
		echo "invalid $f"
	else
		echo "valid $f"
		cp $f b/${g}/
	fi
done
done
