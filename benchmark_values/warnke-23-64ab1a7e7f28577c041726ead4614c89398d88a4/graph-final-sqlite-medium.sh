#!/bin/gnuplot
set terminal pdf size 20,20
set output 'graph-final-sqlite-medium.pdf'
set title 'SQLite medium' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Entry" noenhanced
set ylabel "Operation / Second" noenhanced
plot './benchmark_values_sqlite_mem_1-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 4 title 'insert-ZRam','./benchmark_values_sqlite_mem_1-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 4 title 'update-ZRam','./benchmark_values_sqlite_mem_1-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 4 title 'delete-ZRam','./benchmark_values_sqlite_hdd_1-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 6 title 'insert-HDD','./benchmark_values_sqlite_hdd_1-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 6 title 'update-HDD','./benchmark_values_sqlite_hdd_1-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 6 title 'delete-HDD',
