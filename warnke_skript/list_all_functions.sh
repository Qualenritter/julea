#!/bin/bash
rm -rf tmp build* prefix*

./waf.sh configure --out build_debug --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf) --debug
./waf.sh build
./waf.sh configure --out build_release --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
./waf.sh build

for f in $(find * -name "*.c" | grep -v "test" | grep -v "benchmark" | grep -v "dependencies")
do
	grep -ni "^{" -B1 $f | grep "(" | sed "s/\s*(.*//g" | sed "s/.*-//g" >> tmp
done
for f in $(find build* -name "*.o" -or -name "*.so") $(find build* -executable -type f)
do
	echo $f
	nm $f | grep -i " t " | grep -v "\.isra\." >> tmp
	if [[ $f == *"benchmark"* ]]; then
		objdump -dr $f | grep call | sed "s/.*<//g" | sed "s/[@>].*//g" | grep -v "callq  \*%rax" | grep -v "+" >> tmp3
		objdump -dr $f | grep "lea" | grep "#" | sed "s/.*<//g" | sed "s/>.*//g" >> tmp3
	elif [[ $f == *"test"* ]]; then
		objdump -dr $f | grep call | sed "s/.*<//g" | sed "s/[@>].*//g" | grep -v "callq  \*%rax" | grep -v "+" >> tmp3
		objdump -dr $f | grep "lea" | grep "#" | sed "s/.*<//g" | sed "s/>.*//g" >> tmp3
	elif [[ $f == *"debug"* ]]; then
		objdump -dr $f | grep call | sed "s/.*<//g" | sed "s/[@>].*//g" | grep -v "callq  \*%rax" | grep -v "+" >> tmp2
		objdump -dr $f | grep "lea" | grep "#" | sed "s/.*<//g" | sed "s/>.*//g" >> tmp2
	else
		objdump -dr $f | grep call | sed "s/.*<//g" | sed "s/[@>].*//g" | grep -v "callq  \*%rax" | grep -v "+" >> tmp4
	fi
done

cat tmp | sed "s/.* [tT] //g" | sort | uniq > functions_names_defined.txt
cat tmp2 | sort | uniq > functions_names_used_by_debug.txt
cat tmp4 | sort | uniq > functions_names_used_by_release.txt
cat tmp3 | sort | uniq > functions_names_used_by_test.txt
rm tmp tmp2 tmp3 tmp4
diff functions_names_defined.txt functions_names_used_by_release.txt | grep "<" | sed "s/.*<\s*//g" > function_names_defined_but_not_used.txt
diff functions_names_defined.txt functions_names_used_by_debug.txt | grep "<" | sed "s/.*<\s*//g" > function_names_defined_but_not_used_debug.txt
diff functions_names_defined.txt functions_names_used_by_test.txt | grep "<" | sed "s/.*<\s*//g" > function_names_defined_but_not_used_not_even_in_test.txt
