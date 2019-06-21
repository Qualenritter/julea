files=$(ls afl/start-files/* | grep -v README )
files="${files} $(ls afl/out/*/crashes/* | grep -v README )"
for f in ${files} ;
do
	cat $f | ./build/test-afl/julea-test-afl > /dev/null 2>&1
	r=$?
	if [ $r -eq 0 ]; then
	  echo "invalid $f"
	else
	  echo "valid $f"
	fi
done
