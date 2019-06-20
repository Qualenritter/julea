n_values=(1 5 10 50 100 500 1000 5000 10000 50000 100000 1000000)
for f in $(find -type d | grep -v "^.$"); do
	csv_name=$(echo $f | sed "s/$/.csv/g")
	rm $csv_name
for n in "${n_values[@]}"
do
	val_c=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/create:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_o=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/open:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_d=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/delete:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_cb=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/create-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_ob=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/open-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_db=$(cat "$f/benchmark_values" | grep "/smd/scheme_${n}/delete-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_s=$(cat "$f/benchmark_values_size_${n}_02" | grep smd | sed "s/\s.*//g")
	echo "$n,$val_c,$val_o,$val_d,$val_cb,$val_ob,$val_db,$val_s" >> ${csv_name}
done
done

cat > gnuplot.plot << EOF
set terminal pngcairo size 800,400 enhanced crop
set output 'graph-create.png'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [0:*]
EOF
str=""
for f in $(find -type d | grep -v "^.$"); do
	csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:2 with lines title \"${f:2:10}-no-batch\""
	str="${str}, '${csv_name}' using 1:5 with lines title \"${f:2:10}-batch\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
cat > gnuplot.plot << EOF
set terminal pngcairo size 800,400 enhanced crop
set output 'graph-open.png'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [0:*]
EOF
str=""
for f in $(find -type d | grep -v "^.$"); do
	csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:3 with lines title \"${f:2:10}-no-batch\""
	str="${str}, '${csv_name}' using 1:6 with lines title \"${f:2:10}-batch\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
cat > gnuplot.plot << EOF
set terminal pngcairo size 800,400 enhanced crop
set output 'graph-delete.png'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [0:*]
EOF
str=""
for f in $(find -type d | grep -v "^.$"); do
	csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:4 with lines title \"${f:2:10}-no-batch\""
	str="${str}, '${csv_name}' using 1:7 with lines title \"${f:2:10}-batch\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
cat > gnuplot.plot << EOF
set terminal pngcairo size 800,400 enhanced crop
set output 'graph-size.png'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [0:*]
EOF
str=""
for f in $(find -type d | grep -v "^.$"); do
    csv_name=$(echo $f | sed "s/$/.csv/g")
	str="${str}, '${csv_name}' using 1:8 with lines title\"${f:2:10}\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
rm gnuplot.plot
