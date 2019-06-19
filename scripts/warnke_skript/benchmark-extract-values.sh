n_values=(1 5 10 50 100 500 1000 5000 10000 50000 100000 1000000)
#n_values=(1 2 3 4 5 6 7 8 9 10 20 30 40 50 60 70 80 90 100 200 300 400 500 600 700 800 900 1000 2000 3000 4000 5000 6000 7000 8000 9000 10000 50000 100000)
rm benchmark_values_strassberger.csv
rm benchmark_values_warnke.csv
for n in "${n_values[@]}"
do
	val_c=$(cat benchmark_values_strassberger | grep "/smd/scheme_${n}/create:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_o=$(cat benchmark_values_strassberger | grep "/smd/scheme_${n}/open:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_d=$(cat benchmark_values_strassberger | grep "/smd/scheme_${n}/delete:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_cb=$(cat benchmark_values_strassberger | grep "/smd/scheme_${n}/create-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_ob=$(cat benchmark_values_strassberger | grep "/smd/scheme_${n}/open-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_db=$(cat benchmark_values_strassberger | grep "/smd/scheme_${n}/delete-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_s=$(cat "benchmark_values_strassberger_size_${n}_02" | grep smd | sed "s/\s.*//g")
	echo "$n,$val_c,$val_o,$val_d,$val_cb,$val_ob,$val_db,$val_s" >>benchmark_values_strassberger.csv
	val_c=$(cat benchmark_values_warnke | grep "/smd/scheme_${n}/create:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_o=$(cat benchmark_values_warnke | grep "/smd/scheme_${n}/open:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_d=$(cat benchmark_values_warnke | grep "/smd/scheme_${n}/delete:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_cb=$(cat benchmark_values_warnke | grep "/smd/scheme_${n}/create-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_ob=$(cat benchmark_values_warnke | grep "/smd/scheme_${n}/open-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_db=$(cat benchmark_values_warnke | grep "/smd/scheme_${n}/delete-batch:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
	val_s=$(cat "benchmark_values_warnke_size_${n}_02" | grep smd | sed "s/\s.*//g")
	echo "$n,$val_c,$val_o,$val_d,$val_cb,$val_ob,$val_db,$val_s" >>benchmark_values_warnke.csv
done

gnuplot << EOF
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
plot 'benchmark_values_strassberger.csv' using 1:2 with lines title "s-no-batch", \
	'benchmark_values_strassberger.csv' using 1:5 with lines title "s-batch", \
	'benchmark_values_warnke.csv' using 1:2 with lines title "w-no-batch", \
	'benchmark_values_warnke.csv' using 1:5 with lines title "w-batch"
EOF
gnuplot << EOF
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
plot 'benchmark_values_strassberger.csv' using 1:3 with lines title "s-no-batch", \
	'benchmark_values_strassberger.csv' using 1:6 with lines title "s-batch", \
	'benchmark_values_warnke.csv' using 1:3 with lines title "w-no-batch", \
	'benchmark_values_warnke.csv' using 1:6 with lines title "w-batch"
EOF
gnuplot << EOF
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
plot 'benchmark_values_strassberger.csv' using 1:4 with lines title "s-no-batch", \
	'benchmark_values_strassberger.csv' using 1:7 with lines title "s-batch", \
	'benchmark_values_warnke.csv' using 1:4 with lines title "w-no-batch", \
	'benchmark_values_warnke.csv' using 1:7 with lines title "w-batch"
EOF
gnuplot << EOF
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
plot 'benchmark_values_strassberger.csv' using 1:8 with lines title "s", \
	'benchmark_values_warnke.csv' using 1:8 with lines title "w"
EOF
