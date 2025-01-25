#!/bin/bash
# Start with a 32-bit number

i=4294967295

while true; do

  # Calculate the length in bits
  bits=$(echo "l($i)/l(2)" | bc -l | awk '{print int($0+0.5)}')

  # Double the prime number
  bits2=$(($bits + 1))

  # Generate a prime number around the current number of bits
  prime=$(openssl prime -generate -bits $bits)
  prime2=$(openssl prime -generate -bits $bits2)

  # Calculate the product of the two primes
  fact=$(awk "BEGIN {printf \"%.0f\n\", $prime * $prime2}")

  echo $prime
  echo $prime2
  echo $fact

  # Calculate the length in bits
  factbits=$(echo "l($fact)/l(2)" | bc -l | awk '{print int($0+0.5)}')

  # Print the result
  echo "number of bits: $bits"


  # Run qimcifa with the calculated number
  echo $fact | python3 /FindAFactor/find_a_factor $1

  # Calculate the next power of 2
  i=$(echo "$i * 2" | bc)
done
