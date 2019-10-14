#!/bin/gnuplot
set terminal epslatex size 6in,3in
set output 'graph-final-sqlite-fields.tex'
set title 'SQLite fields'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set key right outside
set yrange [100:55000]
set xrange [6:1000000]
set xlabel "\\#Entry"
set ylabel "Operation / Second"
plot './benchmark_values_sqlite_mem_6-5-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 4 title 'insert-5','./benchmark_values_sqlite_mem_6-5-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 4 title 'update-5','./benchmark_values_sqlite_mem_6-5-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 4 title 'delete-5','./benchmark_values_sqlite_mem_6-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 6 title 'insert-50','./benchmark_values_sqlite_mem_6-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 6 title 'update-50','./benchmark_values_sqlite_mem_6-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 6 title 'delete-50','./benchmark_values_sqlite_mem_6-500-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 8 title 'insert-500','./benchmark_values_sqlite_mem_6-500-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 8 title 'update-500','./benchmark_values_sqlite_mem_6-500-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 8 title 'delete-500',
