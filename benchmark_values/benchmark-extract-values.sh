folders=$(find -type d \
| grep -v "^.$" \
| sort \
| grep -v "warnke-01" \
)
n_values=(1 5 10 50 100 500 1000 5000 10000 50000 100000 1000000)
#/smd/scheme_1/write/db
rm *.csv
for f in ${folders}; do
	csv_name=$(echo $f | sed "s/$/.csv/g")

	for n in $(cat "$f/benchmark_values" | sed "s-.*/smd/--g" | sed "s-/.*--g" | sort -n | uniq)
	do
		val_c=$(cat "$f/benchmark_values" | grep "/smd/${n}/schema/create:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_o=$(cat "$f/benchmark_values" | grep "/smd/${n}/schema/get:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_d=$(cat "$f/benchmark_values" | grep "/smd/${n}/schema/delete:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_cb=$(cat "$f/benchmark_values" | grep "/smd/${n}/schema/create-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_ob=$(cat "$f/benchmark_values" | grep "/smd/${n}/schema/get-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_db=$(cat "$f/benchmark_values" | grep "/smd/${n}/schema/delete-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_i=$(cat "$f/benchmark_values" | grep "/smd/${n}/entry/insert:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_ib=$(cat "$f/benchmark_values" | grep "/smd/${n}/entry/insert-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		if [ -z "$val_c" ]; then val_c=0; fi
		if [ -z "$val_o" ]; then val_o=0; fi
		if [ -z "$val_d" ]; then val_d=0; fi
		if [ -z "$val_cb" ]; then val_cb=0; fi
		if [ -z "$val_ob" ]; then val_ob=0; fi
		if [ -z "$val_db" ]; then val_db=0; fi
		if [ -z "$val_i" ]; then val_i=0; fi
		if [ -z "$val_ib" ]; then val_ib=0; fi
		echo "$n,$val_c,$val_o,$val_d,$val_cb,$val_ob,$val_db,$val_i,$val_ib" >> ${csv_name}
	done
done

#set terminal pngcairo size 800,400 enhanced crop
cat > gnuplot.plot << EOF
set terminal pdf
set output 'graph-create.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [5000:*]
set xlabel "#Datatypes" noenhanced
set ylabel "operation/second" noenhanced
EOF
str=""
for f in ${folders}; do
	csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:2 with lines title \"${f:2:9}-no-batch\""
	str="${str}, '${csv_name}' using 1:5 with lines title \"${f:2:9}-batch\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
cat > gnuplot.plot << EOF
set terminal pdf
set output 'graph-get.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [10000:*]
set xlabel "#Datatypes" noenhanced
set ylabel "operation/second" noenhanced
EOF
str=""
for f in ${folders}; do
	csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:3 with lines title \"${f:2:9}-no-batch\""
	str="${str}, '${csv_name}' using 1:6 with lines title \"${f:2:9}-batch\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
cat > gnuplot.plot << EOF
set terminal pdf
set output 'graph-delete.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [5000:*]
set xlabel "#Datatypes" noenhanced
set ylabel "operation/second" noenhanced
EOF
str=""
for f in ${folders}; do
	csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:4 with lines title \"${f:2:9}-no-batch\""
	str="${str}, '${csv_name}' using 1:7 with lines title \"${f:2:9}-batch\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
cat > gnuplot.plot << EOF
set terminal pdf
set output 'graph-insert.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [1000:*]
set xlabel "#struct{int[100]}; in File" noenhanced
set ylabel "int/second" noenhanced
EOF
str=""
for f in ${folders}; do
    csv_name=$(echo $f | sed "s/$/.csv/g")
        str="${str}, '${csv_name}' using 1:8 with lines title\"${f:2:9}-no-batch\""
        str="${str}, '${csv_name}' using 1:9 with lines title\"${f:2:9}-batch\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
rm gnuplot.plot
