import random
import requests
import time


domains = []
pvs = []
pv_sum = 0.0
with open("domain_pv.txt", "r") as f:
    for line in f.readlines():
        domain = str.split(line[:-1], " ")[0]
        pv = str.split(line[:-1], " ")[1]
        if domain == "Unknow":
            continue
        domains.append( domain )
        pvs.append( float(pv) )

        pv_sum = pv_sum + float(pv)

for index in range(len(pvs)):
    pvs[index] = pvs[index] / pv_sum * 10000

for index in range(1, len(pvs)):
    pvs[index] = pvs[index] + pvs[index - 1]

def random_index(pvs):
    rand = random.random() * 10000
    for index in range(len(pvs)):
        if rand < pvs[index]:
            return index
    
    return -1

while True:
    index = random_index(pvs)
    if index == -1:
        continue
    print("http://" + domains[index])
    try:
        r = requests.get("http://" + domains[index], timeout = 3)
        print( r.status_code )
    except requests.exceptions.ConnectionError:
        print(domain + "ConnectionError")
    except requests.exceptions.ChunkedEncodingError:
        print(domain + "ChunkedEncodingError")
    except:
        print(domain + "An Unknow Error Happened")
