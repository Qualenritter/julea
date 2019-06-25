files=$(ls afl/start-files/* | grep -v README )
files="${files} $(ls afl/out/*/crashes/* | grep -v README )"
rm -rf b
mkdir b
for g in gcc-gcov-debug-asan clang gcc-gcov
do
mkdir b/${g}
for f in ${files}
do
	(export export G_DEBUG=resident-modules; export G_MESSAGES_DEBUG=all; export LD_LIBRARY_PATH=prefix-${g}/lib/:$LD_LIBRARY_PATH; export JULEA_CONFIG=~/.config/julea/julea1; export AFL_USE_ASAN=1; export ASAN_OPTIONS=fast_unwind_on_malloc=0,abort_on_error=1,symbolize=0; cat $f | ./build-${g}/test-afl/julea-test-afl > x 2>&1)
	r=$?
	if [ $r -eq 0 ]; then
		echo "invalid $f $g"
	else
		echo "valid $f $g"
		cp $f b/${g}/
		exit 1
	fi
done
done
