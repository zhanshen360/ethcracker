#!/bin/sh

go run src/ethcracker.go -pk ~/test/pk.txt -t ~/test/templates.txt  -threads 1  -min_len 1 -max_len 30 -v 1 -start_from 30% -re 7  
#go run src/ethcracker.go -pk ~/test/ethwallet-q.json -t ~/test/pattern.txt -presale -threads 4  -min_len 1 -v 1 -start_from 0
# -dump ~/test/v.txt 