#!/bin/bash
for f in $(ls benchmark_values_* | sort)
do
	printf "file" > combined.csv
	for file in $(ls benchmark_values_* | sort | sed "s/benchmark_values_//g")
	do
		file=$(echo $file | sed "s/_/-/g" )
		printf ",$file" >> combined.csv
	done
	printf "\n" >> combined.csv
	while IFS="" read -r attribute || [ -n "$attribute" ]
	do
		attribute=$(echo $attribute | sed "s/:.*//g")
		printf $(echo "$attribute" | sed "s-/1--g" | sed "s-/hdf5/--g" | sed "sx/x-xg") >> combined.csv
		for file in $(ls benchmark_values_* | sort)
		do
			printf "," >> combined.csv
			printf $(cat $file | grep $attribute | sed "s/.*(//g" | sed "s/).*//g" | sed "s-/.*--g" | sed "s/KB/\*1000/g"| sed "s/MB/\*1000000/g"| sed "s/GB/\*1000000000/g" | bc) >> combined.csv
		done
		printf "\n" >> combined.csv
	done < $f
	break;
done

cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output 'hdf5-syntetic-benchmark.pdf'
set title 'HDF5-synthetic benchmarks' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set size ratio 0.5
set logscale y
set key right outside
set style data histogram
set style histogram cluster gap 1
set style fill solid
set boxwidth 0.9
set xtics format ""
set grid ytics
set xlabel "" noenhanced
set ylabel "# Operation or Bytes / second" noenhanced
plot	'combined.csv' using 2:xtic(1) title columnheader(2), \
for [i=3:7] '' using i title columnheader(i)
EOF
cat gnuplot.plot | gnuplot
rm gnuplot.plot
