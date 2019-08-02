set terminal pdf
set output './warnke-8e786c35dac62587166576ec850f332b4a91efaf-graph-entry50.pdf'
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
plot	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-50-entry-insert.csv' using 1:2 with lines title "insert"			,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-50-entry-update.csv' using 1:2 with lines title "update"			,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-50-entry-delete.csv' using 1:2 with lines title "delete"			,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-50-entry-insert-batch.csv' using 1:2 with lines title "insert-batch"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-50-entry-update-batch.csv' using 1:2 with lines title "update-batch"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-50-entry-delete-batch.csv' using 1:2 with lines title "delete-batch"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-50-iterator-single.csv' using 1:2 with lines title "iterator-single"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-50-iterator-all.csv' using 1:2 with lines title "iterator-all"
