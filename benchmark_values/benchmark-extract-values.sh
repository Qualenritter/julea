folders=$(find -type d \
| grep -v "^.$" \
| sort \
| grep -v "warnke-01" \
| grep -v "warnke-02" \
| grep -v "warnke-03" \
| grep -v "warnke-04" \
| grep -v "warnke-05" \
| grep -v "warnke-06" \
| grep -v "warnke-07" \
)
n_values=(1 5 10 50 100 500 1000 5000 10000 50000 100000 1000000)
#/smd/scheme_1/write/db
rm *.csv
for f in ${folders}; do
	csv_name=$(echo $f | sed "s/$/.csv/g")
	for n in "${n_values[@]}"
	do
		val_c=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/create:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_o=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/open:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_d=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/delete:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_cb=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/create-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_ob=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/open-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_db=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/delete-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_w_db=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/write/db:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_r_db=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/read/db:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_w_obj=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/write/object:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_r_obj=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/read/object:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
		val_s_types=$(cat "$f/benchmark_values_size_${n}_02" | grep smd | sed "s/\s.*//g")
		val_s_data=$(cat "$f/benchmark_values_size_${n}_03" | grep smd | sed "s/\s.*//g")
		echo "$n,$val_c,$val_o,$val_d,$val_cb,$val_ob,$val_db,$val_s_types,$val_w_db,$val_r_db,$val_w_obj,$val_r_obj,$val_s_data" >> ${csv_name}
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
set output 'graph-open.pdf'
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
set output 'graph-size-datatypes.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [15:*]
set xlabel "#Datatypes" noenhanced
set ylabel "KB in storage" noenhanced
EOF
str=""
for f in ${folders}; do
    csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:8 with lines title\"${f:2:9}\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat > gnuplot.plot << EOF
set terminal pdf
set output 'graph-size-data.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [15:*]
set xlabel "#struct{int[100]}; in File" noenhanced
set ylabel "KB in storage" noenhanced
EOF
str=""
for f in ${folders}; do
    csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:13 with lines title\"${f:2:8}\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
cat > gnuplot.plot << EOF
set terminal pdf
set output 'graph-write.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [50000:*]
set xlabel "#struct{int[100]}; in File" noenhanced
set ylabel "int/second" noenhanced
EOF
str=""
for f in ${folders}; do
    csv_name=$(echo $f | sed "s/$/.csv/g")
        str="${str}, '${csv_name}' using 1:9 with lines title\"${f:2:9}-db\""
        str="${str}, '${csv_name}' using 1:11 with lines title\"${f:2:9}-obj\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
cat > gnuplot.plot << EOF
set terminal pdf
set output 'graph-read.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [50000:*]
set xlabel "#struct{int[100]}; in File" noenhanced
set ylabel "int/second" noenhanced
EOF
str=""
for f in ${folders}; do
    csv_name=$(echo $f | sed "s/$/.csv/g")
        str="${str}, '${csv_name}' using 1:10 with lines title\"${f:2:9}-db\""
        str="${str}, '${csv_name}' using 1:12 with lines title\"${f:2:9}-obj\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
rm gnuplot.plot
