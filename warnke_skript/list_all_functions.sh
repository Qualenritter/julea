#!/bin/bash
rm tmp
for f in $(find build* -name "*.o" -or -name "*.so" | grep -v "test" | grep -v "benchmark")
do
	nm $f | grep -i " t " | grep -v "\.isra\." >> tmp
done
for f in $(find prefix* -name "*.o" -or -name "*.so" | grep -v "test" | grep -v "benchmark")
do
	nm $f | grep -i " t " | grep -v "\.isra\." >> tmp
done

cat tmp | sed "s/.* [tT] //g" | sort | uniq > all_functions_names.txt
rm tmp
cat all_functions_names.txt
