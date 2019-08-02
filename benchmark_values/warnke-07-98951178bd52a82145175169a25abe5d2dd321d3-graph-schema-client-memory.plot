set terminal pdf
set output './warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-graph-schema-client-memory.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [1000000:*]
set xlabel "#Schema" noenhanced
set ylabel "operation/second" noenhanced
plot	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-new.csv' using 1:2 with lines title "new"		,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-ref.csv' using 1:2 with lines title "ref"		,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-unref.csv' using 1:2 with lines title "unref"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-free.csv' using 1:2 with lines title "free"
