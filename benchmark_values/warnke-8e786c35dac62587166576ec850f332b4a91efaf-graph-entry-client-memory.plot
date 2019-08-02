set terminal pdf
set output './warnke-8e786c35dac62587166576ec850f332b4a91efaf-graph-entry-client-memory.pdf'
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
plot	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-entry-new.csv' using 1:2 with lines title "new"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-entry-ref.csv' using 1:2 with lines title "ref"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-entry-unref.csv' using 1:2 with lines title "unref"	,	'./warnke-8e786c35dac62587166576ec850f332b4a91efaf-entry-free.csv' using 1:2 with lines title "free"
