set terminal pdf
set output './warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-graph-schema-client-field.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [100000:*]
set xlabel "#Schema" noenhanced
set ylabel "operation/second" noenhanced
plot	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-add-field.csv' using 1:2 with lines title "add-field"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-get-field.csv' using 1:2 with lines title "get-field"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-get-fields.csv' using 1:2 with lines title "get-fields"	,	'./warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-equals.csv' using 1:2 with lines title "equals"
