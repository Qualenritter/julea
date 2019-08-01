folders=$(find -type d \
| grep -v "^.$" \
| sort \
| grep -v "warnke-01" \
)
n_values=(1 5 10 50 100 500 1000 5000 10000 50000 100000 1000000)
#/db/scheme_1/write/db
rm *.csv*
for f in ${folders}; do

	for n in $(cat "$f/benchmark_values" | sed "s-.*/db/--g" | sed "s-/.*--g" | sort -n | uniq)
	do
		csv_name=$(echo $f | sed "s/$/-schema.csv/g")
		val_schema_c=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/create:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_o=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/get:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_d=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/delete:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_cb=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/create-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_ob=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/get-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_db=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/delete-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_fa=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/add_field:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_fg=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/get_field:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_fga=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/get_fields:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_schema_e=$(cat "$f/benchmark_values" | grep "/db/${n}/schema/equals:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		if [ -z "$val_schema_c" ]; then val_schema_c=0; fi
		if [ -z "$val_schema_o" ]; then val_schema_o=0; fi
		if [ -z "$val_schema_d" ]; then val_schema_d=0; fi
		if [ -z "$val_schema_cb" ]; then val_schema_cb=0; fi
		if [ -z "$val_schema_ob" ]; then val_schema_ob=0; fi
		if [ -z "$val_schema_db" ]; then val_schema_db=0; fi
		if [ -z "$val_schema_a" ]; then val_schema_a=0; fi
		if [ -z "$val_schema_g" ]; then val_schema_g=0; fi
		if [ -z "$val_schema_ga" ]; then val_schema_ga=0; fi
		if [ -z "$val_schema_e" ]; then val_schema_e=0; fi
		echo "$n,$val_schema_c,$val_schema_o,$val_schema_d,$val_schema_cb,$val_schema_ob,$val_schema_db,$val_schema_a,$val_schema_g,$val_schema_ga,$val_schema_e" >> ${csv_name}
		for n2 in $(cat "$f/benchmark_values" | sed "s-.*/db/${n}/--g" | sed "s-/.*--g" | sort -n | uniq)
		do
			csv_name=$(echo $f | sed "s/$/-entry.csv/g")
			val_entry_i=$(cat "$f/benchmark_values" | grep "/db/${n}/${n2}/entry/insert:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
			val_entry_ib=$(cat "$f/benchmark_values" | grep "/db/${n}/${n2}/entry/insert-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
			val_entry_u=$(cat "$f/benchmark_values" | grep "/db/${n}/${n2}/entry/update:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
			val_entry_ub=$(cat "$f/benchmark_values" | grep "/db/${n}/${n2}/entry/update-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
			val_entry_d=$(cat "$f/benchmark_values" | grep "/db/${n}/${n2}/entry/delete:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
			val_entry_db=$(cat "$f/benchmark_values" | grep "/db/${n}/${n2}/entry/delete-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
			if [ -z "$val_entry_i" ]; then val_entry_i=0; fi
			if [ -z "$val_entry_ib" ]; then val_entry_ib=0; fi
			if [ -z "$val_entry_u" ]; then val_entry_u=0; fi
			if [ -z "$val_entry_ub" ]; then val_entry_ub=0; fi
			if [ -z "$val_entry_d" ]; then val_entry_d=0; fi
			if [ -z "$val_entry_db" ]; then val_entry_db=0; fi
			echo "$n,$val_entry_i,$val_entry_ib,$val_entry_u,$val_entry_ub,$val_entry_d,$val_entry_db" >> ${csv_name}-$n2
		done
	done
done

#set terminal pngcairo size 800,400 enhanced crop
for f in ${folders}
do
f2=$(echo $f| sed "s-./--g")
cat > gnuplot.plot << EOF
set terminal pdf
set output '$f-graph-schema-backend.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [100:*]
set xlabel "#Schema" noenhanced
set ylabel "operation/second" noenhanced
EOF
str=""
csv_name=$(echo $f | sed "s/$/-schema.csv/g")
str="${str}, '${csv_name}' using 1:2 with lines title \"create-no-batch\""
str="${str}, '${csv_name}' using 1:3 with lines title \"update-no-batch\""
str="${str}, '${csv_name}' using 1:4 with lines title \"delete-no-batch\""
str="${str}, '${csv_name}' using 1:5 with lines title \"create-batch\""
str="${str}, '${csv_name}' using 1:6 with lines title \"update-batch\""
str="${str}, '${csv_name}' using 1:7 with lines title \"delete-batch\""
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
done
for f in ${folders}
do
f2=$(echo $f| sed "s-./--g")
cat > gnuplot.plot << EOF
set terminal pdf
set output '$f-graph-schema-client.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [100:*]
set xlabel "#Schema" noenhanced
set ylabel "operation/second" noenhanced
EOF
str=""
csv_name=$(echo $f | sed "s/$/-schema.csv/g")
str="${str}, '${csv_name}' using 1:8 with lines title \"add-field\""
str="${str}, '${csv_name}' using 1:9 with lines title \"get-field\""
str="${str}, '${csv_name}' using 1:10 with lines title \"get-all-fields\""
str="${str}, '${csv_name}' using 1:11 with lines title \"equals\""
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
done
for f in ${folders}
do
for csv_name in $(find . -name "${f2}*.csv-*")
do
n2=$(echo ${csv_name} | sed "s/.*-//g")
cat > gnuplot.plot << EOF
set terminal pdf
set output '$f-graph-entry${n2}.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [100:*]
set xlabel "#Entry" noenhanced
set ylabel "operation/second" noenhanced
EOF
str=""
str="${str}, '${csv_name}' using 1:2 with lines title \"$n2-insert-no-batch\""
str="${str}, '${csv_name}' using 1:4 with lines title \"$n2-update-no-batch\""
str="${str}, '${csv_name}' using 1:6 with lines title \"$n2-delete-no-batch\""
str="${str}, '${csv_name}' using 1:3 with lines title \"$n2-insert-batch\""
str="${str}, '${csv_name}' using 1:5 with lines title \"$n2-update-batch\""
str="${str}, '${csv_name}' using 1:7 with lines title \"$n2-delete-batch\""
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
done
done
rm gnuplot.plot
