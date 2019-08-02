set terminal pdf
set output './warnke-8e786c35dac62587166576ec850f332b4a91efaf-graph-schema-client-field.pdf'
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
plot	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-add-field.csv' using 1:2 with lines title "add-field"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-get-field.csv' using 1:2 with lines title "get-field"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-get-fields.csv' using 1:2 with lines title "get-fields"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-equals.csv' using 1:2 with lines title "equals"
