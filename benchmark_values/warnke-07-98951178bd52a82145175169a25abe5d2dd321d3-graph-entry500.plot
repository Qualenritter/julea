set terminal pdf
set output './warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-graph-entry500.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [100:*]
set xlabel "#Entry" noenhanced
set ylabel "operation/second" noenhanced
plot	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-500-entry-insert.csv' using 1:2 with lines title "insert"			,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-500-entry-update.csv' using 1:2 with lines title "update"			,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-500-entry-delete.csv' using 1:2 with lines title "delete"			,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-500-entry-insert-batch.csv' using 1:2 with lines title "insert-batch"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-500-entry-update-batch.csv' using 1:2 with lines title "update-batch"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-500-entry-delete-batch.csv' using 1:2 with lines title "delete-batch"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-500-iterator-single.csv' using 1:2 with lines title "iterator-single"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-500-iterator-all.csv' using 1:2 with lines title "iterator-all"
