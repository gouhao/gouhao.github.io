folder=`ls`
for f in $folder
do
	if [ -d $f ]; then
		cd $f
		rm merged merged1 merged2 merged3 merged-bak perf/ raw/ list review r m p t tmp -rf
		cd ../
	fi
done
