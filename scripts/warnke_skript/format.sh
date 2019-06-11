for f in $(find . -type f -name "*.h" -o -name "*.c" | grep -v not-formatted-header.h);do
	echo $f
	clang-format -i $f
done

