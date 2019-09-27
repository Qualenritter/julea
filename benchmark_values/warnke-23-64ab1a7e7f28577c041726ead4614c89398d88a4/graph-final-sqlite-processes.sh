#!/bin/gnuplot
set terminal pdf size 8,5
set output 'graph-final-sqlite-processes.pdf'
set title 'SQLite processes' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set key right outside
set yrange [8000:26000]
set xrange [6:1000000]
set xlabel "#Entry" noenhanced
set ylabel "Operation / Second" noenhanced
plot './benchmark_values_sqlite_mem_1-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 4 title 'insert-1','./benchmark_values_sqlite_mem_1-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 4 title 'update-1','./benchmark_values_sqlite_mem_1-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 4 title 'delete-1','./benchmark_values_sqlite_mem_6-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 6 title 'insert-6','./benchmark_values_sqlite_mem_6-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 6 title 'update-6','./benchmark_values_sqlite_mem_6-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 6 title 'delete-6',
