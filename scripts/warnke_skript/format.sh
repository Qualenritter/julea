for f in $(find . -type f -name "*.h" -o -name "*.c" | grep -v not-formatted-header.h | grep -v prefix | grep -v spack);do
	echo $f
	clang-format -i $f
done

