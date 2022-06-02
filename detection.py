import os
import math
import sympy
import numpy as np
from sklearn.linear_model import LinearRegression
from itertools import combinations, groupby

def get_fps() -> dict:
    fp_os = dict()
    with open("fps.txt", "r") as f:
        for line in f.readlines():
            if line[0] == '#' or line[0] == '\n':
                continue
            line = str.strip(line)
            items = str.split(line, ' ')
            fp_os[items[0]] = list()
            for os in str.split(items[1], ','):
                
                fp_os[items[0]].append(os)
    # print( len(fp_os) )
    return fp_os

class Windows_Pkt:
    def __init__(self, rt, dst_ip, ip_id):
        self.rt = float( rt )
        self.dst_ip = dst_ip
        self.dst_ip_B = ".".join(str.split(dst_ip, ".")[0:2])
        self.ip_id = int( ip_id )

# 检测是否为单一 Windows, 是输出 True
def dect_windows(tra):
    pkt_list = list()
    for _ in tra[1]:
        pkt = Windows_Pkt(_[0], _[2], _[3])
        pkt_list.append(pkt)

    # Windows 11 检测
    pkt_list = sorted( pkt_list, key = lambda x: x.dst_ip )
    dst_ip_len = dict()
    for _dst_ip, _pkts in groupby(pkt_list, key = lambda x: x.dst_ip):
        _pkts = sorted(_pkts, key = lambda x: x.rt)

        ip_id_seq_list = list()
        for _pkt in _pkts:
            flag_added = False
            for index in range(len(ip_id_seq_list)):
                temp = abs(_pkt.ip_id - ip_id_seq_list[index][-1])
                temp_2 = abs(_pkt.ip_id + 65535 - ip_id_seq_list[index][-1])
                if (temp < 10 or temp_2 < 10):
                    ip_id_seq_list[index].append(_pkt.ip_id)
                    flag_added = True
                    break
            
            if not flag_added:
                ip_id_seq = []
                ip_id_seq.append( _pkt.ip_id )
                ip_id_seq_list.append( ip_id_seq )
    
        dst_ip_len[_dst_ip] = len(ip_id_seq_list)

    multi_sip = False
    for dip, cnt in dst_ip_len.items():
        if cnt > 1:
            multi_sip = True

    if not multi_sip:
        return True

    # Windows 10 检测
    pkt_list = sorted( pkt_list, key = lambda x: x.dst_ip_B )
    dst_ip_b_len = dict()
    for _dst_ip_b, _pkts in groupby(pkt_list, key = lambda x: x.dst_ip_B):
        _pkts = sorted(_pkts, key = lambda x: x.rt)

        dip_last_index = dict()
        dip_last_ipids = dict()
        ip_id_seq_list = list()

        for _index, _pkt in enumerate(_pkts):
            flag_added = False

            if _pkt.dst_ip not in dip_last_ipids.keys():
                dip_last_ipids[_pkt.dst_ip] = list()
                jmp_b = 0
            else:
                jmp_b = _index - dip_last_index[_pkt.dst_ip] - 1
            
            for ip_id_seq in dip_last_ipids[_pkt.dst_ip]:
                temp = abs(_pkt.ip_id - ip_id_seq[-1] - jmp_b)
                temp_2 = abs(_pkt.ip_id + 32767 - ip_id_seq[-1] - jmp_b)
                if (temp < 10 or temp_2 < 10):
                    ip_id_seq.append(_pkt.ip_id)
                    flag_added = True
                    break
            
            if not flag_added:
                ip_id_seq = []
                ip_id_seq.append( _pkt.ip_id )
                dip_last_ipids[_pkt.dst_ip].append( ip_id_seq )

            dip_last_index[_pkt.dst_ip] = _index
    
        dst_ip_b_len[_dst_ip_b] = dip_last_ipids
    
    multi_sip = False
    for dip_b, dip_last_ipids in dst_ip_b_len.items():
        for dip, ip_id_seq in dip_last_ipids.items():
            if len(ip_id_seq) > 1:
                multi_sip = True

    if not multi_sip:
        return True

    _pkts = sorted(pkt_list, key = lambda x: x.rt)
    ip_id_seq_list = list()
    for _pkt in _pkts:
        flag_added = False
        for index in range(len(ip_id_seq_list)):
            temp = abs(_pkt.ip_id - ip_id_seq_list[index][-1])
            temp_2 = abs(_pkt.ip_id + 32767 - ip_id_seq_list[index][-1])
            if (temp < 10 or temp_2 < 10):
                ip_id_seq_list[index].append(_pkt.ip_id)
                flag_added = True
                break
        
        if not flag_added:
            ip_id_seq = []
            ip_id_seq.append( _pkt.ip_id )
            ip_id_seq_list.append( ip_id_seq )

    if len(ip_id_seq_list) > 1:
        return False
    else:
        return True

# 检测是否为单一 Linux
def dect_linux(tra):
    dstIP_srcIP_set = set()
    dstIP_rt_dict = {}
    dstIP_tv_dict = {}
    for pkt in tra[1]:
        if len(pkt) == 8 and pkt[4] == "....S.": # 65535:64:0:60:M1460,S,T,N,W8:.
            if pkt[2] not in dstIP_srcIP_set:
                dstIP_srcIP_set.add(pkt[2])
                dstIP_rt_dict[pkt[2]] = []
                dstIP_tv_dict[pkt[2]] = []

            dstIP_rt_dict[pkt[2]].append( float(pkt[0]) )
            dstIP_tv_dict[pkt[2]].append( float(pkt[7]) )
    
    for dst_ip in dstIP_srcIP_set:
        if len( dstIP_rt_dict[dst_ip] ) < 5:
            continue

        X = dstIP_rt_dict[dst_ip]
        Y = dstIP_tv_dict[dst_ip]

        X_train = np.array(X).reshape((len(X), 1))
        Y_train = np.array(Y).reshape((len(Y), 1))

        model = LinearRegression()
        model.fit(X_train, Y_train)

        #用训练后的模型，进行预测
        Y_predict = model.predict(X_train)
    
        #coef_是系数，intercept_是截距
        a1 = model.coef_[0][0]
        b = model.intercept_[0]
        # print("y=%.4f*x+%.4f" % (a1,b))
        # print("得分", model.score(X_train, Y_train))
        if a1 < 0.0 or a1 > 1020.0:
            return False

        if model.score(X_train, Y_train) < 0.95:
            return False

    return True

# 检测是否为单一 XNU
def dect_XNU(tra):
    port_lists = list()
    for pkt in tra[1]:
        if len(pkt) >= 7 and pkt[4] == "....S.": # 65535:64:0:60:M1460,S,T,N,W8:.
            port = int(pkt[6])

            flag_added = False
            for index in range(len(port_lists)):
                temp = abs(port - port_lists[index][-1])
                temp_2 = abs(port + 65535 - 49152 - port_lists[index][-1])
                if (temp < 5 or temp_2 < 5):
                    port_lists[index].append(port)
                    flag_added = True
                    break
                
            if not flag_added:
                port_list = []
                port_list.append( port )
                port_lists.append( port_list )

    if len(port_lists) > 2:
        return False
    else:
        return True

# 单独基于全局 IPID
def dect_db1(tra):
    pkt_list = list()
    for _ in tra[1]:
        pkt = Windows_Pkt(_[0], _[2], _[3])
        pkt_list.append(pkt)

    _pkts = sorted(pkt_list, key = lambda x: x.rt)
    ip_id_seq_list = list()
    for _pkt in _pkts:
        flag_added = False
        for index in range(len(ip_id_seq_list)):
            temp = abs(_pkt.ip_id - ip_id_seq_list[index][-1])
            temp_2 = abs(_pkt.ip_id + 32767 - ip_id_seq_list[index][-1])
            if (temp < 10 or temp_2 < 10):
                ip_id_seq_list[index].append(_pkt.ip_id)
                flag_added = True
                break
        
        if not flag_added:
            ip_id_seq = []
            ip_id_seq.append( _pkt.ip_id )
            ip_id_seq_list.append( ip_id_seq )

    if len(ip_id_seq_list) > 1:
        return False
    else:
        return True

# 单独基于全局 时间戳
def dect_db2(tra):
    dstIP_rts = list()
    dstIP_tvs = list()
    for pkt in tra[1]:
        if len(pkt) == 8 and pkt[4] == "....S.": # 65535:64:0:60:M1460,S,T,N,W8:.
            dstIP_rts.append( float(pkt[0]) )
            dstIP_tvs.append( float(pkt[7]) )

    if len(dstIP_rts) == 0:
        return False
    
    X = dstIP_rts
    Y = dstIP_tvs

    X_train = np.array(X).reshape((len(X), 1))
    Y_train = np.array(Y).reshape((len(Y), 1))

    model = LinearRegression()
    model.fit(X_train, Y_train)

    #用训练后的模型，进行预测
    Y_predict = model.predict(X_train)

    #coef_是系数，intercept_是截距
    a1 = model.coef_[0][0]
    b = model.intercept_[0]
    # print("y=%.4f*x+%.4f" % (a1,b))
    # print("得分", model.score(X_train, Y_train))
    if a1 < 0.0 or a1 > 1020.0:
        return False

    if model.score(X_train, Y_train) < 0.95:
        return False

    return True

# 对非共享接入IP流量进行检测
def dection(traffics: list, fp_os: dict):
    # print(len(traffics))

    Fall = 0
    TN = 0
    FP = 0

    TN2 = 0
    FP2 = 0

    TN3 = 0
    FP3 = 0

    for index, tra in enumerate(traffics):
        # print(tra[0] + " NO." + str(index) + " -> ", end="")
        Fall = Fall + 1
        oss = dict()
        for pkt in tra[1]:
            if len(pkt) > 4 and pkt[4] == "....S.": # 65535:64:0:60:M1460,S,T,N,W8:.
                items = str.split(pkt[5], ':')
                fp = ':'.join(items[:-1])
                if fp in fp_os.keys():
                    os_str = ','.join(fp_os[fp])
                    # 如果要加上具体的"操作系统名"，可加上这行代码
                    # os_str = os_str + "_" + fp
                    if os_str not in oss.keys():
                        oss[os_str] = 1
                    oss[os_str] = oss[os_str] + 1
                else:
                    tmp = "unknown_" + fp
                    if tmp not in oss.keys():
                        oss[tmp] = 1
                    oss[tmp] = oss[tmp] + 1
        
        max_fp_cnt, all_fp_cnt = 0, 0
        os_name = ""
        for os,cnt in oss.items():
            if cnt > max_fp_cnt:
                max_fp_cnt = cnt
                os_name = os
            all_fp_cnt = all_fp_cnt + cnt
            # print(os, end=":")
            # print(cnt, end=" ")

        if index == 165:
            a = 1 + 1
        
        single = False
        if all_fp_cnt == 0:
            # print(single)
            TN = TN + 1
            continue

        if max_fp_cnt / all_fp_cnt > 0.95:
            # 同一操作系统
            if os_name == "Windows":
                single = dect_windows(tra)
            elif os_name == "Linux":
                single = dect_linux(tra)
            else:
                single = dect_XNU(tra)
        else:
            # 不同操作系统
            single = False

        # print(single)
        if single:
            TN = TN + 1
        else:
            FP = FP + 1

    for index, tra in enumerate(traffics):
        single = dect_db1(tra)
        if single:
            TN2 = TN2 + 1
        else:
            FP2 = FP2 + 1
        
    for index, tra in enumerate(traffics):
        single = dect_db2(tra)
        if single:
            TN3 = TN3 + 1
        else:
            FP3 = FP3 + 1

    return Fall, TN, FP, TN2, FP2, TN3, FP3

# 对共享接入IP流量进性检测
def dection_sip(traffics: list, fp_os: dict, interval_time: str, total_time: int):
    # 正流量样本
    straffics = list()
    big_traffics = list()
    traffics = sorted(traffics, key=lambda x: x[0])
    stra_cnt = int(total_time / int(interval_time) * 10)

    dev_tra_cnt = sympy.Symbol('x')
    root = sympy.solve(dev_tra_cnt**2 - dev_tra_cnt - 2 * stra_cnt, dev_tra_cnt)
    root1 = eval(str(root[0]), {"sqrt":math.sqrt})
    root2 = eval(str(root[1]), {"sqrt":math.sqrt})
    if root1 > 0:
        root = root1
    else:
        root = root2
    dev_tra_cnt = round(root/10 + 0.1)
    # print(interval_time, end=' : ')
    # print(dev_tra_cnt)

    for dev_name, de_tra in groupby(traffics, key=lambda x: x[0]):
        de_tra = sorted(de_tra, key=lambda x:x[2])
        big_traffics = big_traffics + de_tra[0:dev_tra_cnt]

    for tra in combinations(big_traffics, 2):
        # traffic_cnt = traffic_cnt + 1
        # print(x)
        straffics.append([[tra[0][0], tra[1][0]], tra[0][1] + tra[1][1], tra[0][2] + tra[1][2]])
    # straffics = sorted(straffics, key=lambda tra : tra[2], reverse=True)

    for index, _ in enumerate(straffics):
        straffics[index][1] = sorted(straffics[index][1], key=lambda x: float(x[0]))

    Fall = 0
    TP = 0
    FN = 0

    TP2 = 0
    FN2 = 0

    TP3 = 0
    FN3 = 0

    for tra in straffics:
        # print(tra[0][0], end=" | ")
        # print(tra[0][1], end=" -> ")
        Fall = Fall + 1
        oss = dict()
        for pkt in tra[1]:
            if len(pkt) > 4 and pkt[4] == "....S.": # 65535:64:0:60:M1460,S,T,N,W8:.
                items = str.split(pkt[5], ':')
                fp = ':'.join(items[:-1])
                if fp in fp_os.keys():
                    os_str = ','.join(fp_os[fp])
                    # 如果要加上具体的"操作系统名"，可加上这行代码
                    # os_str = os_str + "_" + fp
                    if os_str not in oss.keys():
                        oss[os_str] = 1
                    oss[os_str] = oss[os_str] + 1
                else:
                    tmp = "unknown_" + fp
                    if tmp not in oss.keys():
                        oss[tmp] = 1
                    oss[tmp] = oss[tmp] + 1
        
        max_fp_cnt, all_fp_cnt = 0, 0
        os_name = ""
        for os,cnt in oss.items():
            if cnt > max_fp_cnt:
                max_fp_cnt = cnt
                os_name = os
            all_fp_cnt = all_fp_cnt + cnt
            # print(os, end=":")
            # print(cnt, end=" ")

        single = False
        if all_fp_cnt == 0:
            # print(not single)
            FN = FN + 1
            continue

        if max_fp_cnt / all_fp_cnt > 0.95:
            # 同一操作系统
            if os_name == "Windows":
                single = dect_windows(tra)
            elif os_name == "Linux":
                single = dect_linux(tra)
            else:
                single = dect_XNU(tra)
            single = not single
        else:
            # 不同操作系统
            single = True

        # print(single)
        if single:
            TP = TP + 1
        else:
            FN = FN + 1

    for tra in straffics:
        single = not dect_db1(tra)
        if single:
            TP2 = TP2 + 1
        else:
            FN2 = FN2 + 1
        
    for tra in straffics:
        single = not dect_db2(tra)
        if single:
            TP3 = TP3 + 1
        else:
            FN3 = FN3 + 1

    return Fall, TP, FN, TP2, FN2, TP3, FN3

if __name__ == "__main__":
    total_time = 3600 # 一共1小时，3600秒
    fp_os = get_fps()
    main_dir = os.listdir("SUB_FEATUREs")

    # main_dir = ["60"]

    for interval_time in main_dir:
        # 负流量样本
        traffics = list()
        time_dir = os.path.join("SUB_FEATUREs", interval_time) # time_dir : SUB_FEATUREs/180
        for dev in os.listdir(time_dir):
            dev_dir = os.path.join(time_dir, dev) # dev_dir : SUB_FEATUREs/180/Windows_7
            dev_tra_cnt = total_time / int(interval_time)
            for sub_file in os.listdir(dev_dir)[0:int(dev_tra_cnt)]:
                sub_file = os.path.join(dev_dir, sub_file)
                # sub_file : SUB_FEATUREs/180/Windows_7/X_00000_20220210090615.txt
                with open(sub_file, "r") as f:
                    line_cnt = 0
                    pkts = list()
                    for line in f.readlines():
                        if line[0] == '\n':
                            continue
                        line_cnt = line_cnt + 1
                        line = str.strip(line)
                        items = str.split(line, ' ')
                        pkts.append(items)
                    traffics.append( [str.split(sub_file, "/")[2], pkts, line_cnt] )

        neg_all, TN, FP, TN2, FP2, TN3, FP3 = dection(traffics, fp_os)
        pos_all, TP, FN, TP2, FN2, TP3, FN3 = dection_sip(traffics, fp_os, interval_time, total_time)
        A = (TP + TN) / (TP + TN + FP + FN)
        P = TP / (TP + FP)
        R = TP / (TP + FN)
        print("样本流量持续时长 {} 分钟时本文方法：正样本数量 {}；负样本数量 {}；准确率 {}；精准率 {}；召回率 {}；F1值 {}".format(int(interval_time)/60, pos_all, neg_all, A, P, R, 2 * P * R/(P + R)))

        P2 = TP2 / (TP2 + FP2)
        R2 = TP2 / (TP2 + FN2)
        A2 = (TP2 + TN2) / (TP2 + TN2 + FP2 + FN2)
        print("样本流量持续时长 {} 分钟时Bellovin [9]提出的方法：正样本数量 {}；负样本数量 {}；准确率 {}；精准率 {}；召回率 {}；F1值 {}".format(int(interval_time)/60, pos_all, neg_all, A2, P2, R2, 2 * P2 * R2/(P2 + R2)))

        P3 = TP3 / (TP3 + FP3)
        R3 = TP3 / (TP3 + FN3)
        A3 = (TP3 + TN3) / (TP3 + TN3 + FP3 + FN3)
        print("样本流量持续时长 {} 分钟时Wicherski 等 [6]提出的方法：正样本数量 {}；负样本数量 {}；准确率 {}；精准率 {}；召回率 {}；F1值 {}".format(int(interval_time)/60, pos_all, neg_all, A3, P3, R3, 2 * P3 * R3/(P3 + R3)))
