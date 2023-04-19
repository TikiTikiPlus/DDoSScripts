yyyy=2018
for (( m=9;m<=12;m++ )); do
	mm=`printf "%02d" $m`
	d=0
	# week 1
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 2
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 3
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4'
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

done
yyyy=2019
for (( m=1;m<=12;m++ )); do
	mm=`printf "%02d" $m`
	d=0
	# week 1
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 2
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 3
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4'
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

done

yyyy=2020
for (( m=1;m<=12;m++ )); do
	mm=`printf "%02d" $m`
	d=0
	# week 1
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 2
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 3
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4'
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

done

yyyy=2021
for (( m=1;m<=12;m++ )); do
	mm=`printf "%02d" $m`
	d=0
	# week 1
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 2
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 3
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4'
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

done

yyyy=2022
for (( m=1;m<=12;m++ )); do
	mm=`printf "%02d" $m`
	d=0
	# week 1
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 2
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 3
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4'
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

done

yyyy=2023
for (( m=1;m<=2;m++ )); do
	mm=`printf "%02d" $m`
	d=0
	# week 1
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 2
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

	# week 3
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 


	# week 4'
	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log &

	d=$((d+1))
	dd=`printf "%02d" $d`
	# block
	./rav_attack_count.py  --minimum-packets 5 -t 60 --use-seconds-per-window $yyyy/$yyyy-$mm-$dd*gz > $yyyy/attacks-$yyyy-$mm-$dd.psv 2> $yyyy/attacks-$yyyy-$mm-$dd.log 

done


