set terminal pdf
set output './warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-graph-schema-backend.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [100:*]
set xlabel "#Schema" noenhanced
set ylabel "operation/second" noenhanced
plot	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-create.csv' using 1:2 with lines title "create"		,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-get.csv' using 1:2 with lines title "get"			,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-delete.csv' using 1:2 with lines title "delete"		,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-create-batch.csv' using 1:2 with lines title "create-batch"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-get-batch.csv' using 1:2 with lines title "get-batch"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-delete-batch.csv' using 1:2 with lines title "delete-batch"
