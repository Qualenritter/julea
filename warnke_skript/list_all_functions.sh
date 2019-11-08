#!/bin/bash
rm -rf functions_names*
rm -rf build* prefix*

./waf.sh configure --out build_debug --debug
./waf.sh build
./waf.sh configure --out build_release
./waf.sh build

for f in $(find * -name "*.c" | grep -v "test" | grep -v "benchmark" | grep -v "dependencies")
do
	grep -ni "^{" -B1 $f | grep "(" | sed "s/\s*(.*//g" | sed "s/.*-//g" | sed "s/.*\s\+//g">> tmp
done
for f in $(find build* -name "*.o" -or -name "*.so") $(find build* -executable -type f)
do
	echo $f
	nm $f | grep -i " t " \
		| sed "s/\.isra\..*//g" \
		| sed "s/\.constprop\..*//g" \
		| sed "s/\.cold\..*//g" \
		| sed "s/\.part\..*//g" \
		| sed "s/\.localalias\..*//g" \
		 >> tmp
	if [[ $f == *"benchmark"* ]]; then
		objdump -dr $f | grep call | sed "s/.*<//g" | sed "s/[@>].*//g" | grep -v "callq  \*%rax" | grep -v "+" >> tmp3
		objdump -dr $f | grep "lea" | grep "#" | sed "s/.*<//g" | sed "s/>.*//g" | grep -v "+" >> tmp3
	elif [[ $f == *"test"* ]]; then
		objdump -dr $f | grep call | sed "s/.*<//g" | sed "s/[@>].*//g" | grep -v "callq  \*%rax" | grep -v "+" >> tmp3
		objdump -dr $f | grep "lea" | grep "#" | sed "s/.*<//g" | sed "s/>.*//g" | grep -v "+" >> tmp3
	elif [[ $f == *"debug"* ]]; then
		objdump -dr $f | grep call | sed "s/.*<//g" | sed "s/[@>].*//g" | grep -v "callq  \*%rax" | grep -v "+" >> tmp2
		objdump -dr $f | grep "lea" | grep "#" | sed "s/.*<//g" | sed "s/>.*//g" | grep -v "+" >> tmp2
	else
		objdump -dr $f | grep call | sed "s/.*<//g" | sed "s/[@>].*//g" | grep -v "callq  \*%rax" | grep -v "+" >> tmp4
	fi
done

rm -rf build*
grep -rni --exclude-dir=dependencies "^\s*\..* = " | sed "s/.* = //g" | sed "s/,.*//g" | grep -v " " | sort | uniq > tmp5
grep -rnw --exclude-dir=dependencies "G_PRIVATE_INIT" | sed "s/.*(//g" | sed "s/).*//g" >> tmp5

#ignore some functions
cat >> tmp5 << EOF
__do_global_dtors_aux
__do_global_dtors_aux_fini_array_entry
__init_array_start
_fini
_j_message_new_reply
_start
backend_info
frame_dummy
fstat
H5PLget_plugin_type
j_init
register_tm_clones
EOF

cat tmp5 >> tmp2
cat tmp5 >> tmp3
cat tmp5 >> tmp4
cat tmp2 >> tmp3
cat tmp | sed "s/.* [tT] //g" | sort | uniq > functions_names_defined.txt
cat tmp2 | sort | uniq > functions_names_used_by_debug.txt
cat tmp4 | sort | uniq > functions_names_used_by_release.txt
cat tmp3 | sort | uniq > functions_names_used_by_test.txt
cat tmp5 | sort | uniq > functions_names_used_by_structs.txt
rm tmp tmp2 tmp3 tmp4 tmp5
diff functions_names_defined.txt functions_names_used_by_release.txt | grep "<" | sed "s/.*<\s*//g" > functions_names_defined_but_not_used.txt
diff functions_names_defined.txt functions_names_used_by_debug.txt | grep "<" | sed "s/.*<\s*//g" > functions_names_defined_but_not_used_debug.txt
diff functions_names_defined.txt functions_names_used_by_test.txt | grep "<" | sed "s/.*<\s*//g" > functions_names_defined_but_not_used_not_even_in_test.txt

for f in $(cat functions_names_defined_but_not_used_not_even_in_test.txt)
do
	echo $f
	grep -rnw $f --exclude-dir=dependencies | grep -v "functions_names_" | grep -v "benchmark_values"
done
