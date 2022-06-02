# host_ip_1 = "192.168.47.129"
# host_ip_2 = "192.168.47.131"

import os
from itertools import groupby
import matplotlib
import matplotlib.pyplot as plt

class XNU_Pkt:
    def __init__(self, rt, src_ip, dst_ip, ip_id):
        self.rt = float( rt )
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_ip_B = ".".join(str.split(dst_ip, "."))
        self.ip_id = int( ip_id )

if __name__ == "__main__":

    pkt_list = []

    with open("/home/xmr/Doc/expr_1/Windows/windows_two.txt", "r") as f:
        lines = f.readlines()

        for line in lines:
            line = line.strip()
            items = str.split(line, " ")

            host_ip_1 = "192.168.47.129"
            host_ip_2 = "192.168.47.131"

            src_ip = ""
            if( items[1] == "TCP" ):
                src_ip = items[3]
            else:
                src_ip = items[2]

            if ((src_ip != host_ip_2)): # 只需要向外发出的流量, windows
                continue

            if( items[1] == "TCP" ):
                pkt = Windows_Pkt(items[0], items[3], items[4], items[7])
            else:
                pkt = Windows_Pkt(items[0], items[2], items[3], items[4])

            pkt_list.append(pkt)

    
    # groupby : 
    pkt_list = sorted( pkt_list, key = lambda x: x.dst_ip )

    for _dst_ip, _pkts in groupby(pkt_list, key = lambda x: x.dst_ip):
        print( _dst_ip )

        _pkts = sorted(_pkts, key = lambda x: x.rt)

        rt_seq_list = list()
        ip_id_seq_list = list()
        for _pkt in _pkts:
            flag_added = False
            for index in range(len(ip_id_seq_list)):
                temp = _pkt.ip_id - ip_id_seq_list[index][-1]
                temp_2 = abs(temp)
                if (temp == 1 or temp_2 < 5 or temp_2 > 65530):
                    ip_id_seq_list[index].append(_pkt.ip_id)
                    rt_seq_list[index].append(_pkt.rt)
                    flag_added = True
                    continue
            
            if not flag_added:
                ip_id_seq = []
                ip_id_seq.append( _pkt.ip_id )
                ip_id_seq_list.append( ip_id_seq )

                rt_seq = []
                rt_seq.append( _pkt.rt )
                rt_seq_list.append( rt_seq )


        src_ip_set = set()
        for _pkt in _pkts:
            src_ip_set.add( _pkt.src_ip )


        if _dst_ip == "204.79.197.219":
            x = rt_seq_list[0]
            y = ip_id_seq_list[0]
            plt.scatter(x, y, marker='+', color = 'red')

            # x = rt_seq_list[1]
            # y = ip_id_seq_list[1]
            # plt.scatter(x, y, marker='x', color = 'red')
            
            plt.title(" IP-ID for 204.79.197.219 ")

            plt.xlabel('Time')

            plt.ylabel('IP-ID')

            
            plt.legend(loc="right",numpoints=1,labels=['host_1'], fontsize=10)

            # matplotlib.rc("font",family='MicroSoft YaHei',weight="bold")
            # plt.figure(dpi=100)
            plt.rcParams['savefig.dpi'] = 900 #图片像素
            plt.rcParams['figure.dpi'] = 300 #分辨率
            
            plt.savefig('/home/xmr/Doc/expr_1/Windows/windows_one.jpg')


            # plt.show()
            plt.pause(0.5)
            plt.close()

        print( len(src_ip_set), len(ip_id_seq_list), len(_pkts) )

