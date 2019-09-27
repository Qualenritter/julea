#!/bin/gnuplot
set terminal pdf size 8,5
set output 'graph-final-database-6.pdf'
set title 'Database 6' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set key right outside
set yrange [7000:60000]
set xrange [6:1000000]
set xlabel "#Entry" noenhanced
set ylabel "Operation / Second" noenhanced
plot './benchmark_values_mysql_mem_6-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 4 title 'insert-MySQL','./benchmark_values_mysql_mem_6-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 4 title 'update-MySQL','./benchmark_values_mysql_mem_6-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 4 title 'delete-MySQL','./benchmark_values_sqlite_mem_6-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 6 title 'insert-SQLite','./benchmark_values_sqlite_mem_6-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 6 title 'update-SQLite','./benchmark_values_sqlite_mem_6-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 6 title 'delete-SQLite',
