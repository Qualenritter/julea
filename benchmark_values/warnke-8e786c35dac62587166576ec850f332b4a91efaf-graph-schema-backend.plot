set terminal pdf
set output './warnke-8e786c35dac62587166576ec850f332b4a91efaf-graph-schema-backend.pdf'
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
plot	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-create.csv' using 1:2 with lines title "create"		,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-get.csv' using 1:2 with lines title "get"			,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-delete.csv' using 1:2 with lines title "delete"		,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-create-batch.csv' using 1:2 with lines title "create-batch"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-get-batch.csv' using 1:2 with lines title "get-batch"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-delete-batch.csv' using 1:2 with lines title "delete-batch"
