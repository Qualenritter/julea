set terminal pdf
set output 'progress-schema-ref.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Entry" noenhanced
set ylabel "operation/second" noenhanced
plot './warnke-07-98951178bd52a82145175169a25abe5d2dd321d3-schema-ref.csv' using 1:2 with lines title "07", './warnke-8e786c35dac62587166576ec850f332b4a91efaf-schema-ref.csv' using 1:2 with lines title "8e786"
