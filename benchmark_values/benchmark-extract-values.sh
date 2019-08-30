folders=$(find -type d \
| grep -v "^.$" \
| sort \
| grep -v "debug" \
| grep -v "warnke-ssd-m2-01" \
| grep -v "warnke-ssd-m2-02" \
| grep -v "warnke-ssd-m2-03" \
| grep -v "warnke-ssd-m2-04" \
| grep -v "warnke-ssd-m2-05" \
| grep -v "warnke-ssd-m2-06" \
| grep -v "warnke-ssd-m2-07" \
)

#/db/scheme_1/write/db
rm *.csv tmp *.plot *.pdf
for f in ${folders}
do
	for x in $(cat "$f/benchmark_values" | grep seconds | sed "s-.*/db/--g" | sed "s-:.*--g" | sed "s-^[^/]*/--g" | sort -n | uniq)
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
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output '$f-graph-schema-backend.pdf'
set title 'graph-schema-backend' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Schema" noenhanced
set ylabel "operation/second" noenhanced
plot	'$f-schema-create.csv'		using 1:2 with linespoints lc 1 pt 4 title "create"		,\
	'$f-schema-get.csv'		using 1:2 with linespoints lc 2 pt 4 title "get"		,\
	'$f-schema-delete.csv'		using 1:2 with linespoints lc 3 pt 4 title "delete"		,\
	'$f-schema-create-batch.csv'	using 1:2 with linespoints lc 1 pt 6 title "create-batch"	,\
	'$f-schema-get-batch.csv'	using 1:2 with linespoints lc 2 pt 6 title "get-batch"	,\
	'$f-schema-delete-batch.csv'	using 1:2 with linespoints lc 3 pt 6 title "delete-batch"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-schema-backend.plot
done


for f in ${folders}
do
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output '$f-graph-schema-client-field.pdf'
set title 'graph-schema-client-field' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Fields" noenhanced
set ylabel "operation/second" noenhanced
plot	'$f-schema-add-field.csv'	using 1:2 with linespoints lc 1 pt 4 title "add-field"	,\
	'$f-schema-get-field.csv'	using 1:2 with linespoints lc 2 pt 4 title "get-field"	,\
	'$f-schema-get-fields.csv'	using 1:2 with linespoints lc 3 pt 4 title "get-fields"	,\
	'$f-schema-equals.csv'		using 1:2 with linespoints lc 4 pt 4 title "equals"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-schema-client-field.plot
done


for f in ${folders}
do
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output '$f-graph-schema-client-memory.pdf'
set title 'graph-schema-client-memory' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Nothing" noenhanced
set ylabel "operation/second" noenhanced
plot	'$f-schema-new.csv'	using 1:2 with linespoints lc 1 pt 4 title "new"	,\
	'$f-schema-ref.csv'	using 1:2 with linespoints lc 2 pt 4 title "ref"	,\
	'$f-schema-unref.csv'	using 1:2 with linespoints lc 3 pt 4 title "unref"	,\
	'$f-schema-free.csv'	using 1:2 with linespoints lc 4 pt 4 title "free"
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
set terminal pdf size 20,20
set output '$f-graph-entry${n2}.pdf'
set title 'graph-entry${n2}' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Entry" noenhanced
set ylabel "operation/second" noenhanced
plot	'$f-${n2}-entry-insert.csv'				using 1:2 with linespoints lc 1 pt  4 title "insert"				,\
	'$f-${n2}-entry-update.csv'				using 1:2 with linespoints lc 2 pt  4 title "update"				,\
	'$f-${n2}-entry-delete.csv'				using 1:2 with linespoints lc 3 pt  4 title "delete"				,\
	'$f-${n2}-entry-insert-batch.csv'			using 1:2 with linespoints lc 1 pt  6 title "insert-batch"			,\
	'$f-${n2}-entry-update-batch.csv'			using 1:2 with linespoints lc 2 pt  6 title "update-batch"			,\
	'$f-${n2}-entry-delete-batch.csv'			using 1:2 with linespoints lc 3 pt  6 title "delete-batch"			,\
	'$f-${n2}-iterator-single.csv'				using 1:2 with linespoints lc 4 pt  6 title "iterator-single"			,\
	'$f-${n2}-iterator-all.csv'				using 1:2 with linespoints lc 5 pt  6 title "iterator-all"			,\
	'$f-${n2}-entry-insert-batch-index.csv'			using 1:2 with linespoints lc 1 pt  8 title "insert-batch-index"		,\
	'$f-${n2}-entry-update-batch-index.csv'			using 1:2 with linespoints lc 2 pt  8 title "update-batch-index"		,\
	'$f-${n2}-entry-delete-batch-index.csv'			using 1:2 with linespoints lc 3 pt  8 title "delete-batch-index"		,\
	'$f-${n2}-iterator-single-index.csv'			using 1:2 with linespoints lc 4 pt  8 title "iterator-single-index"		,\
	'$f-${n2}-iterator-all-index.csv'			using 1:2 with linespoints lc 5 pt  8 title "iterator-all-index"		,\
	'$f-${n2}-entry-insert-batch-index-atomicity.csv'	using 1:2 with linespoints lc 1 pt 12 title "insert-batch-index-atomicity"	,\
	'$f-${n2}-entry-update-batch-index-atomicity.csv'	using 1:2 with linespoints lc 2 pt 12 title "update-batch-index-atomicity"	,\
	'$f-${n2}-entry-delete-batch-index-atomicity.csv'	using 1:2 with linespoints lc 3 pt 12 title "delete-batch-index-atomicity"	,\
	'$f-${n2}-iterator-single-index-atomicity.csv'		using 1:2 with linespoints lc 4 pt 12 title "iterator-single-index-atomicity"	,\
	'$f-${n2}-iterator-all-index-atomicity.csv'		using 1:2 with linespoints lc 5 pt 12 title "iterator-all-index-atomicity"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-entry${n2}.plot
done
done


for f in ${folders}
do
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output '$f-graph-entry-client-memory.pdf'
set title 'graph-entry-client-memory' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Nothing" noenhanced
set ylabel "operation/second" noenhanced
plot	'$f-entry-new.csv'	using 1:2 with linespoints lc 1 pt 4 title "new"	,\
	'$f-entry-ref.csv'	using 1:2 with linespoints lc 2 pt 4 title "ref"	,\
	'$f-entry-unref.csv'	using 1:2 with linespoints lc 3 pt 4 title "unref"	,\
	'$f-entry-free.csv'	using 1:2 with linespoints lc 4 pt 4 title "free"
EOF
cat gnuplot.plot | gnuplot
mv gnuplot.plot $f-graph-entry-client-memory.plot
done

for t in $(cat tmp)
do
y=$(echo $t | sed "s,/,-,g" | sed "s,_,-,g")
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output 'progress-$y.pdf'
set title '$y' noenhanced
set datafile separator ","
set xtics nomirror rotate by -20
set auto x
set size ratio 0.5
set logscale x
set logscale y
set key right outside
set xlabel "#Elements" noenhanced
set ylabel "operation/second" noenhanced
EOF
str=""
for f in ${folders}
do
	x=$(echo $f | sed "s/.*warnke-//g" | sed "s/-[^-]*$//g")
	str="${str}, '$f-$y.csv' using 1:2 with linespoints title \"${x:0:10}\""
done
str="plot${str:1}"
echo $str >> gnuplot.plot
cat gnuplot.plot | gnuplot
mv gnuplot.plot progress-$y.plot
done

find . -size  0 -print0 |xargs -0 rm --
rm tmp *.plot

pdfunite progress-* progress.pdf
rm progress-*.pdf

for f in ${folders}
do
	pdfunite $f-*.pdf $f.pdf
	rm $f-*.pdf
done

