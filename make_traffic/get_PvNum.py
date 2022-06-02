import requests
import json
import os
    
domains = []
with open("domain_list.txt", "r") as f:
    for line in f.readlines():
        domains.append( line[:-1] )

with open("domain_pv.txt", "w") as f:
    for domain in domains:
        url = "http://apidatav2.chinaz.com/single/alexa?key=d04300741e994e07858337ad8d3c4035&domain=" + domain
        print(url)
        try:
            r = requests.get(url, timeout = 10)
            d = json.loads(r.text)
            pv = d["Result"]["PvNum"]
            x = domain + " " + str(pv)
            print(x)
            f.write(x)
            f.write("\n")
        except:
            print("Unknow Error!")
