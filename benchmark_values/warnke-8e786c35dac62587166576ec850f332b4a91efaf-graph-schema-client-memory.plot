set terminal pdf
set output './warnke-8e786c35dac62587166576ec850f332b4a91efaf-graph-schema-client-memory.pdf'
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
plot	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-new.csv' using 1:2 with lines title "new"		,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-ref.csv' using 1:2 with lines title "ref"		,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-unref.csv' using 1:2 with lines title "unref"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-free.csv' using 1:2 with lines title "free"
