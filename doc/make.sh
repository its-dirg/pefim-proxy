#!/bin/sh
rm -f pefimproxy*
sphinx-apidoc -F -o ../doc/ ../src/pefimproxy
make clean
make html