files=$(find -name "benchmark_values_*")

#/db/scheme_1/write/db
rm *.csv tmp *.plot *.pdf
for f in ${files}
do
	for x in $(cat "$f" | grep seconds | sed "s-.*/db/--g" | sed "s- .*--g" | sed "s-^[^/]*/--g" | sort -n | uniq)
	do
		echo $x >> tmp
	done
done
cat tmp | sort | uniq > tmp2
mv tmp2 tmp

for f in ${files}
do
	for t in $(cat tmp)
	do
		echo "0,0" >> $f-$(echo $t | sed "s,/,-,g" | sed "s,_,-,g").csv
	done
	for n in $(cat "$f" | grep seconds | sed "s-.*/db/--g" | sed "s-/.*--g" | sort -n | uniq)
	do
		for t in $(cat tmp)
		do
			x=$(cat "$f" | grep "/db/${n}/$t " | sed -e "s/.*(//g" | sed -e "s-/.*--g")
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
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output 'graph-schema-backend.pdf'
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
EOF
i=0
for f in ${files}
do
	f_short_name=$(echo $f | sed "s-./benchmark_values_--g" | sed "s/_/-/g")
	if [ "$i" == "0" ]; then
		printf "plot" >> gnuplot.plot
	else
		printf "," >> gnuplot.plot
	fi
	printf	" '$f-schema-create.csv'	using 1:2 with linespoints lc 1 pt 4 dt $i title '${f_short_name}-create'"	 >> gnuplot.plot
	printf	",'$f-schema-get.csv'		using 1:2 with linespoints lc 2 pt 4 dt $i title '${f_short_name}-get'"		 >> gnuplot.plot
	printf	",'$f-schema-delete.csv'	using 1:2 with linespoints lc 3 pt 4 dt $i title '${f_short_name}-delete'"	 >> gnuplot.plot
	printf	",'$f-schema-create-batch.csv'	using 1:2 with linespoints lc 1 pt 6 dt $i title '${f_short_name}-create-batch'" >> gnuplot.plot
	printf	",'$f-schema-get-batch.csv'	using 1:2 with linespoints lc 2 pt 6 dt $i title '${f_short_name}-get-batch'"	 >> gnuplot.plot
	printf	",'$f-schema-delete-batch.csv'	using 1:2 with linespoints lc 3 pt 6 dt $i title '${f_short_name}-delete-batch'" >> gnuplot.plot
	i=$(($i + 1))
done
cat gnuplot.plot | gnuplot
mv gnuplot.plot graph-schema-backend.plot


for f in ${files}
do
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output 'graph-schema-client-field.pdf'
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
mv gnuplot.plot graph-schema-client-field.plot
break
done


for f in ${files}
do
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output 'graph-schema-client-memory.pdf'
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
mv gnuplot.plot graph-schema-client-memory.plot
break
done


for n2 in $(cat tmp | sed "s-/.*--g")
do
if ! [[ "$n2" =~ ^[0-9]+$ ]]
then
	continue
fi
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output 'graph-entry${n2}.pdf'
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
EOF
i=0
for f in ${files}
do
	f_short_name=$(echo $f | sed "s-./benchmark_values_--g" | sed "s/_/-/g")
	if [ "$i" == "0" ]; then
		printf "plot" >> gnuplot.plot
	else
		printf "," >> gnuplot.plot
	fi
	printf  " '$f-${n2}-entry-insert.csv'				using 1:2 with linespoints lc 1 pt  4 dt $i title '${f_short_name}-insert'"				>> gnuplot.plot
	printf  ",'$f-${n2}-entry-update.csv'				using 1:2 with linespoints lc 2 pt  4 dt $i title '${f_short_name}-update'"				>> gnuplot.plot
	printf  ",'$f-${n2}-entry-delete.csv'				using 1:2 with linespoints lc 3 pt  4 dt $i title '${f_short_name}-delete'"				>> gnuplot.plot
	printf  ",'$f-${n2}-entry-insert-batch.csv'			using 1:2 with linespoints lc 1 pt  6 dt $i title '${f_short_name}-insert-batch'"			>> gnuplot.plot
	printf  ",'$f-${n2}-entry-update-batch.csv'			using 1:2 with linespoints lc 2 pt  6 dt $i title '${f_short_name}-update-batch'"			>> gnuplot.plot
	printf  ",'$f-${n2}-entry-delete-batch.csv'			using 1:2 with linespoints lc 3 pt  6 dt $i title '${f_short_name}-delete-batch'"			>> gnuplot.plot
	printf  ",'$f-${n2}-iterator-single.csv'			using 1:2 with linespoints lc 4 pt  6 dt $i title '${f_short_name}-iterator-single'"			>> gnuplot.plot
	printf  ",'$f-${n2}-iterator-all.csv'				using 1:2 with linespoints lc 5 pt  6 dt $i title '${f_short_name}-iterator-all'"			>> gnuplot.plot
	printf  ",'$f-${n2}-entry-insert-batch-index.csv'		using 1:2 with linespoints lc 1 pt  8 dt $i title '${f_short_name}-insert-batch-index'"			>> gnuplot.plot
	printf  ",'$f-${n2}-entry-update-batch-index.csv'		using 1:2 with linespoints lc 2 pt  8 dt $i title '${f_short_name}-update-batch-index'"			>> gnuplot.plot
	printf  ",'$f-${n2}-entry-delete-batch-index.csv'		using 1:2 with linespoints lc 3 pt  8 dt $i title '${f_short_name}-delete-batch-index'"			>> gnuplot.plot
	printf  ",'$f-${n2}-iterator-single-index.csv'			using 1:2 with linespoints lc 4 pt  8 dt $i title '${f_short_name}-iterator-single-index'"		>> gnuplot.plot
	printf  ",'$f-${n2}-iterator-all-index.csv'			using 1:2 with linespoints lc 5 pt  8 dt $i title '${f_short_name}-iterator-all-index'"			>> gnuplot.plot
	printf  ",'$f-${n2}-entry-insert-batch-index-atomicity.csv'	using 1:2 with linespoints lc 1 pt 12 dt $i title '${f_short_name}-insert-batch-index-atomicity'"	>> gnuplot.plot
	printf  ",'$f-${n2}-entry-update-batch-index-atomicity.csv'	using 1:2 with linespoints lc 2 pt 12 dt $i title '${f_short_name}-update-batch-index-atomicity'"	>> gnuplot.plot
	printf  ",'$f-${n2}-entry-delete-batch-index-atomicity.csv'	using 1:2 with linespoints lc 3 pt 12 dt $i title '${f_short_name}-delete-batch-index-atomicity'"	>> gnuplot.plot
	printf  ",'$f-${n2}-iterator-single-index-atomicity.csv'	using 1:2 with linespoints lc 4 pt 12 dt $i title '${f_short_name}-iterator-single-index-atomicity'"	>> gnuplot.plot
	printf  ",'$f-${n2}-iterator-all-index-atomicity.csv'		using 1:2 with linespoints lc 5 pt 12 dt $i title '${f_short_name}-iterator-all-index-atomicity'"	>> gnuplot.plot
	i=$(($i + 1))
done
cat gnuplot.plot | gnuplot
mv gnuplot.plot graph-entry${n2}.plot
done


for f in ${files}
do
cat > gnuplot.plot << EOF
set terminal pdf size 20,20
set output 'graph-entry-client-memory.pdf'
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
mv gnuplot.plot graph-entry-client-memory.plot
break
done

#find . -size  0 -print0 |xargs -0 rm --
#rm tmp *.plot

pdfunite *.pdf combined.pdf

