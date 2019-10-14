#!/bin/gnuplot
set terminal epslatex size 6in,3in
set output 'graph-final-mysql-medium.tex'
set title 'MySQL medium'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [50:60000]
set xrange [6:1000000]
set xlabel "\\#Entry"
set ylabel "Operation / Second"
plot './benchmark_values_mysql_mem_6-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 4 title 'insert-ZRam','./benchmark_values_mysql_mem_6-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 4 title 'update-ZRam','./benchmark_values_mysql_mem_6-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 4 title 'delete-ZRam','./benchmark_values_mysql_hdd_6-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 6 title 'insert-HDD','./benchmark_values_mysql_hdd_6-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 6 title 'update-HDD','./benchmark_values_mysql_hdd_6-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 6 title 'delete-HDD',
