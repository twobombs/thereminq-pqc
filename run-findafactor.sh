#!/bin/bash
#

for i in {65535..4294967295..65535}
    do
	prime=$(matho-primes -c 1 -u $i)
	echo $(($prime + $prime)) > i2
	i2=$(<i2)
	prime2=$(matho-primes -c 1 -u $i2)
	echo $(($prime * $prime2)) > fact
	fact=$(<fact)
	python3 findafactor $fact
done
