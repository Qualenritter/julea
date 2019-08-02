folders=$(find -type d \
| grep -v "^.$" \
| sort \
| grep -v "debug" \
| grep -v "warnke-01" \
| grep -v "warnke-02" \
| grep -v "warnke-03" \
| grep -v "warnke-04" \
| grep -v "warnke-05" \
| grep -v "warnke-06" \
)
n_values=(1 5 10 50 100 500 1000 5000 10000 50000 100000 1000000)
#/db/scheme_1/write/db
rm *.csv
rm tmp
for f in ${folders}
do
	for x in $(cat "$f/benchmark_values" | sed "s-.*/db/--g" | sed "s-:.*--g" | sed "s-^[^/]*/--g" | sort -n | uniq)
	do
		echo $x >> tmp
	done
done
cat tmp | sort | uniq > tmp2
mv tmp2 tmp

for f in ${folders}
do
	for t in $(cat tmp)
	do
		echo "0,0" >> $f-$(echo $t | sed "s,/,-,g" | sed "s,_,-,g").csv
	done
	for n in $(cat "$f/benchmark_values" | sed "s-.*/db/--g" | sed "s-/.*--g" | sort -n | uniq)
	do
		for t in $(cat tmp)
		do
			x=$(cat "$f/benchmark_values" | grep "/db/${n}/$t:" | sed -e "s/.*(//g" | sed -e "s-/.*--g")
			if [ -z "$x" ]
			then
				x=0
			fi
			if [[ "$x" -ne 0 ]]
			then
				echo "$n,$x" >> $f-$(echo $t | sed "s,/,-,g" | sed "s,_,-,g").csv
			fi
		done
	done
done


#set terminal pngcairo size 800,400 enhanced crop
for f in ${folders}
do
f2=$(echo $f| sed "s-./--g")
cat > gnuplot.plot << EOF
set terminal pdf
set output '$f-graph-schema-backend.pdf'
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
plot	'$f-schema-create.csv' using 1:2 with lines title "create"		,\
	'$f-schema-get.csv' using 1:2 with lines title "get"			,\
	'$f-schema-delete.csv' using 1:2 with lines title "delete"		,\
	'$f-schema-create-batch.csv' using 1:2 with lines title "create-batch"	,\
	'$f-schema-get-batch.csv' using 1:2 with lines title "get-batch"	,\
	'$f-schema-delete-batch.csv' using 1:2 with lines title "delete-batch"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-schema-backend.plot
done


for f in ${folders}
do
f2=$(echo $f| sed "s-./--g")
cat > gnuplot.plot << EOF
set terminal pdf
set output '$f-graph-schema-client-field.pdf'
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
plot	'$f-schema-add-field.csv' using 1:2 with lines title "add-field"	,\
	'$f-schema-get-field.csv' using 1:2 with lines title "get-field"	,\
	'$f-schema-get-fields.csv' using 1:2 with lines title "get-fields"	,\
	'$f-schema-equals.csv' using 1:2 with lines title "equals"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-schema-client-field.plot
done


for f in ${folders}
do
f2=$(echo $f| sed "s-./--g")
cat > gnuplot.plot << EOF
set terminal pdf
set output '$f-graph-schema-client-memory.pdf'
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
plot	'$f-schema-new.csv' using 1:2 with lines title "new"		,\
	'$f-schema-ref.csv' using 1:2 with lines title "ref"		,\
	'$f-schema-unref.csv' using 1:2 with lines title "unref"	,\
	'$f-schema-free.csv' using 1:2 with lines title "free"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-schema-client-memory.plot
done


for f in ${folders}
do
for n2 in $(cat tmp | sed "s-/.*--g")
do
if ! [[ "$n2" =~ ^[0-9]+$ ]]
then
	continue
fi
cat > gnuplot.plot << EOF
set terminal pdf
set output '$f-graph-entry${n2}.pdf'
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
plot	'$f-${n2}-entry-insert.csv' using 1:2 with lines title "insert"			,\
	'$f-${n2}-entry-update.csv' using 1:2 with lines title "update"			,\
	'$f-${n2}-entry-delete.csv' using 1:2 with lines title "delete"			,\
	'$f-${n2}-entry-insert-batch.csv' using 1:2 with lines title "insert-batch"	,\
	'$f-${n2}-entry-update-batch.csv' using 1:2 with lines title "update-batch"	,\
	'$f-${n2}-entry-delete-batch.csv' using 1:2 with lines title "delete-batch"	,\
	'$f-${n2}-iterator-single.csv' using 1:2 with lines title "iterator-single"	,\
	'$f-${n2}-iterator-all.csv' using 1:2 with lines title "iterator-all"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-entry${n2}.plot
done
done


for f in ${folders}
do
f2=$(echo $f| sed "s-./--g")
cat > gnuplot.plot << EOF
set terminal pdf
set output '$f-graph-entry-client-memory.pdf'
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set yrange [1000000:*]
set xlabel "#Entry" noenhanced
set ylabel "operation/second" noenhanced
plot	'$f-entry-new.csv' using 1:2 with lines title "new"	,\
	'$f-entry-ref.csv' using 1:2 with lines title "ref"	,\
	'$f-entry-unref.csv' using 1:2 with lines title "unref"	,\
	'$f-entry-free.csv' using 1:2 with lines title "free"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-entry-client-memory.plot
done
rm gnuplot.plot
rm tmp
find . -size  0 -print0 |xargs -0 rm --
