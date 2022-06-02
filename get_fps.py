import os
import json
from xml.dom.minidom import parse
import xml.dom.minidom

# 额外增加：
# 65535:64:1:64:M1460,N,W6,N,N,T,S,E XNU

def get_zardaxt_data():
    fp_set = dict()

    with open("zardaxt/database/combined.json", "r") as f:
        json_str = ""
        for line in f.readlines():
            line = str.strip(line)
            json_str = json_str + line

        jsons = json.loads(json_str)
        # print(len(jsons))
        for item in jsons:
            if item["tcp_flags"] != 2:
                continue

            if "tcp_window_size" in item:
                fp = str(item["tcp_window_size"]) + ":"
            else:
                continue

            if "ip_ttl" in item:
                if item["ip_ttl"] > 128 and item["ip_ttl"] <= 255:
                    fp = fp + "255" + ":"
                elif item["ip_ttl"] > 64 and item["ip_ttl"] <= 128:
                    fp = fp + "128" + ":"
                elif item["ip_ttl"] > 32 and item["ip_ttl"] <= 64:
                    fp = fp + "64" + ":"
                else:
                    continue
                # fp = fp + str(item["ip_ttl"]) + ":"
            else:
                continue

            if "ip_df" in item:
                fp = fp + str(item["ip_df"]) + ":"
            else:
                continue

            if "tcp_header_length" in item:
                fp = fp + str(int(item["tcp_header_length"] / 4 + 20)) + ":"
            else:
                continue

            if "tcp_options" in item:
                fp = fp + item["tcp_options"][:-1]
                # if item["tcp_options"][:-1] == "M1325,S,T,N,W7":
                #     input()
            else:
                continue

            if "os" in item and "name" in item["os"]:
                os = item["os"]["name"]
            else:
                continue

            if os == "Android":
                os = "Linux"
            if os == "macOS":
                os = "XNU"
            if os == "iOS":
                os = "XNU"
            if os == "Chrome OS":
                continue

            if os == "Windows":
                continue

            if fp not in fp_set.keys():
                fp_set[fp] = dict()

            if os not in fp_set[fp]:
                fp_set[fp][os] = 1

            fp_set[fp][os] = fp_set[fp][os] + 1

    rfp_set = dict()
    for fp, os_dict in fp_set.items():
        flag = False
        for os, cnt in os_dict.items():
            if cnt > 5:
                flag = True

        if flag:
            rfp_set[fp] = set()
            for os, cnt in os_dict.items():
                if cnt > 5:
                    rfp_set[fp].add(os)

    return rfp_set

def get_satori_data():
    fp_set = dict()
    DomTree = xml.dom.minidom.parse("satori/fingerprints/tcp.xml")
    fp_xml = DomTree.documentElement
    
    fps = fp_xml.getElementsByTagName("fingerprint")

    for fp in fps:
        os_class = fp.getAttribute("os_class")
        if os_class == "":
            continue
        if os_class != "Windows" and os_class != "Linux" and os_class != "Mac OS" and os_class != "iOS" and os_class != "Android" and os_class != "Apple TV OS":
            continue
        if os_class == "Mac OS" or os_class == "iOS" or os_class == "Apple TV OS":
            os_class = "XNU"
        if os_class == "Android":
            os_class = "Linux"
        # print( fp.getAttribute("os_class") )
        tcp_tests = fp.getElementsByTagName("test")
        # tests = tcp_tests.getElementsByTagName("test")
        for test in tcp_tests:
            tcp_flag = test.getAttribute("tcpflag")
            if tcp_flag != "S":
                continue
            tcp_fp = test.getAttribute("tcpsig")
            tcp_fp = str.split(tcp_fp, ":")
            tcp_fp = ":".join(tcp_fp[:-1])

            if tcp_fp.endswith(",E,E"):
                tcp_fp = tcp_fp[:-2]

            if tcp_fp not in fp_set.keys():
                fp_set[tcp_fp] = set()

            fp_set[tcp_fp].add(os_class)
    
    return fp_set

if __name__ == "__main__":
    # linux 230
    # windows 196
    # XNU 124

    # 510
    # fp_set_1 = get_zardaxt_data()
    # print("# zardaxt_data: " + str(len(fp_set_1)) )
        
    # 127
    fp_set_2 = get_satori_data()
    print("# satori_data: " + str(len(fp_set_2)) )

    # for fp, oss in fp_set_2.items():
    #     if fp in fp_set_1.keys():
    #         for os in oss:
    #             fp_set_1[fp].add(os)
    #     else:
    #         fp_set_1[fp] = fp_set_2[fp]

    fp_set_all = fp_set_2

    print("# fp_set_all: " + str(len(fp_set_all)) )

    linux_fp = 0
    windows_fp = 0
    xnu_fp = 0
    multi_os_fp = 0

    for fp, oss in fp_set_all.items():
        if len(oss) > 1:
            multi_os_fp = multi_os_fp + 1
        elif list(oss)[0] == "Linux":
            linux_fp = linux_fp + 1
        elif list(oss)[0] == "Windows":
            windows_fp = windows_fp + 1
        else:
            xnu_fp = xnu_fp + 1 
    
    print("# linux_fp: " + str(linux_fp))
    print("# windows_fp: " + str(windows_fp))
    print("# xnu_fp: " + str(xnu_fp))
    print("# multi_os_fp: " + str(multi_os_fp))

    for fp, oss in fp_set_all.items():
        print(fp, end=" ")
        os_cnt = len(oss)
        index = 0
        for os in oss:
            if index != len(oss) - 1:
                print(os, end=",")
                index = index + 1
            else:
                print(os)
