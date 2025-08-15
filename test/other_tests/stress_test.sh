#!/bin/bash

c=0
for i in {1..1000}
do
    ./a.out 2>&1 1> /dev/null
    if [ $? -eq 139 ]
    then
        echo "Segfault $c/$i"
        let c++
    fi
done

echo "Segfault $c/$i"