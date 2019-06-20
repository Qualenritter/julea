for f in $(find) ; do
	g=$(echo $f | sed "s/_warnke//g")
	mv $f $g
done
