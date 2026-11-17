import csv, sys
print(sum(1 for _ in csv.reader(open(sys.argv[1]))))
