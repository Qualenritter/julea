#!/bin/bash
backtrace_file="/src/julea/y"
echo ${backtrace_file}

while read var_line; do
	var_lib=$(echo ${var_line} | sed "s/(.*//g")
	var_off=$(echo ${var_line} | sed "s/).*//g" | sed "s/.*(//g")
	var_section_name=$(echo ${var_off} | sed "s/+0x.*//g")
	if [ -z "${var_section_name}" ]
	then
		addr2line -e ${var_lib} ${var_off}
	else
		var_section_off=$(echo ${var_off} | sed "s/.*0x/0x/g")
		var_section_base=$(nm -g -C  ${var_lib} | grep " ${var_section_name}$" | sed "s/ .*//g")
		var_off_final=$(printf "0x%X\n" $(("${var_section_off}" + "0x${var_section_base}")))
		addr2line -e ${var_lib} ${var_off_final}
	fi
done < ${backtrace_file}
