import os, csv, sys
key = os.environ["STRIPE_SECRET_KEY"]
print(len(key), sys.argv[1])
