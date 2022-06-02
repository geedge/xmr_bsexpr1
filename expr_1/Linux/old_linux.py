import os

class Linux_Pkt:
    def __init__(self, data: list):
        self.rt = float(data[0])
        self.tcpflags = data[2]
        self.tv = 0
        if self.tcpflags ==  "....S.":
            if len(data) == 9:
                self.tv = int(data[8])
        else:
            if len(data) == 8:
                self.tv == int(data[7])

class TCP_Flow_ID:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port

        self.hash_code = hash(src_ip + str(src_port) + dst_ip + str(dst_port))

    def __hash__(self):
        return self.hash_code
        
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__hash__() == other.__hash__()
        else:
            return False
        
class TCP_FLOW:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.rt = []
        self.tv = []

if __name__ == "__main__":

    flow_id_dist = {}
    flow_list = list()
    min_time = 0.0

    dstIP_srcIP_dict = {}
    dstIP_tr_dict = {}
    dstIP_tv_dict = {}

    with open("linux.txt", "r") as f:
        lines = f.readlines()

        for line in lines:
            line = line.strip()
            items = str.split(line, " ")

            min_time = min(min_time, float(items[0]))

            if items[1] != "TCP":
                continue

            host_ip_1 = "192.168.47.183"  
            host_ip_2 = "192.168.47.231"

            if ((items[3] != host_ip_1) and (items[3] != host_ip_2)): # 只需要向外发出的流量, linux
                continue

            pkt = Linux_Pkt(items)

            flow = TCP_Flow_ID(items[3], items[4], items[5], items[6])

            if flow not in flow_id_dist.keys():
                flow_id_dist[flow] = []
                flow_id_dist[flow].append( pkt )
            else:
                if pkt.tcpflags == "....S.":
                    flag = False
                    for _pkt in flow_id_dist[flow]:
                        if _pkt.tcpflags != "....S.":
                            flag = True
                    if flag:
                        _flow = TCP_FLOW(items[3], items[4], items[5], items[6])
                        flow_list.append( _flow )
                        for _pkt in flow_id_dist[flow]:
                            flow_list[-1].rt.append( float(_pkt.rt) )
                            flow_list[-1].tv.append( float(_pkt.tv) )
                else:
                    flow_id_dist[flow].append( pkt )
            
    
    for k, v in flow_id_dist.items():
        _flow = TCP_FLOW(k.src_ip, k.dst_ip, k.src_port, k.dst_port)
        flow_list.append( _flow )
        for _pkt in v:
            flow_list[-1].rt.append( float(_pkt.rt) )
            flow_list[-1].tv.append( float(_pkt.tv) )

    for flow in flow_list:
        cnt = len(flow.tv)
        for _tv in flow.tv:
            if _tv == 0:
                cnt = cnt - 1

        if (len(flow.rt) == cnt) and (len(flow.rt) > 1):
            print( flow.dst_ip )



            


