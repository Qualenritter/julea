set terminal pdf size 20,20
set output 'graph-final-mysql-fields.pdf'
set title 'MySQL fields' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Entry" noenhanced
set ylabel "Operation / Second" noenhanced
plot './benchmark_values_mysql_mem_1-5-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 4 title 'insert-5',
'./benchmark_values_mysql_mem_1-5-entry-update-batch-index.csv'			using 1:2 with linespoints lc 2 pt 4 title 'update-5',
'./benchmark_values_mysql_mem_1-5-entry-delete-batch-index.csv'			using 1:2 with linespoints lc 3 pt 4 title 'delete-5',
'./benchmark_values_mysql_mem_1-50-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 6 title 'insert-50',
'./benchmark_values_mysql_mem_1-50-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 6 title 'update-50',
'./benchmark_values_mysql_mem_1-50-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 6 title 'delete-50',
'./benchmark_values_mysql_mem_1-500-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt 8 title 'insert-500',
'./benchmark_values_mysql_mem_1-500-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt 8 title 'update-500',
'./benchmark_values_mysql_mem_1-500-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt 8 title 'delete-500',
