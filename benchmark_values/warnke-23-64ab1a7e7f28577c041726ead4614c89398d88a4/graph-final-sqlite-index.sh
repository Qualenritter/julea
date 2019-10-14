#!/bin/gnuplot
set terminal epslatex size 6in,3in
set output 'graph-final-sqlite-index.tex'
set title 'SQLite index'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set key right outside
set yrange [200:26000]
set xrange [6:1000000]
set xlabel "\\#Entry"
set ylabel "Operation / Second"
plot './benchmark_values_sqlite_mem_6-50-entry-insert-batch.csv'			using 1:2 with linespoints lc 1 pt 4 title 'insert','./benchmark_values_sqlite_mem_6-50-entry-update-batch.csv'			using 1:2 with linespoints lc 2 pt 4 title 'update','./benchmark_values_sqlite_mem_6-50-entry-delete-batch.csv'			using 1:2 with linespoints lc 3 pt 4 title 'delete','./benchmark_values_sqlite_mem_6-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 6 title 'insert-index','./benchmark_values_sqlite_mem_6-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 6 title 'update-index','./benchmark_values_sqlite_mem_6-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 6 title 'delete-index',
