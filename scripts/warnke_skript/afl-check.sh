for f in $(ls afl/out/*/crashes/* | grep -v README )
do
	rm -rf /mnt2/julea/*
	cat  $f | ./build/test-afl/julea-test-afl
done
