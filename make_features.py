import os
import shutil

if __name__ == "__main__":
    files = os.listdir("PCAPs")
    
    devices = []
    for file in files:
        if file[-5:] == ".pcap":
            device = str.split(file, ".")[0]
            device = str.split(device, "_")[:-1]
            device = "_".join(device)
            devices.append(device)

    delta_times = [60, 120, 180, 240, 300]

    if os.path.exists("SUB_PCAPs"):
        shutil.rmtree("SUB_PCAPs")
    os.mkdir("SUB_PCAPs")

    for delta_time in delta_times:
        os.mkdir("SUB_PCAPs/" + str(delta_time))

    for delta_time in delta_times:
        for device in devices:
            print("SUB_PCAPs/" + str(delta_time) + "/" + device)
            os.mkdir("SUB_PCAPs/" + str(delta_time) + "/" + device)
            # print( "tshark -X lua_script:feature.lua -r " + device + "_1.pcap " )
            print("editcap -i " + str(delta_time) + " PCAPs/" + device + "_1.pcap" + " SUB_PCAPs/" + str(delta_time) + "/" + device + "/X.pcap")
            os.system("editcap -i " + str(delta_time) + " PCAPs/" + device + "_1.pcap" + " SUB_PCAPs/" + str(delta_time) + "/" + device + "/X.pcap")
            # os.system("tshark -X lua_script:feature.lua -r " + device + "_1")

            

    if os.path.exists("SUB_FEATUREs"):
        shutil.rmtree("SUB_FEATUREs")
    os.mkdir("SUB_FEATUREs")

    for delta_time in delta_times:
        os.mkdir("SUB_FEATUREs/" + str(delta_time))

    for delta_time in delta_times:
        for device in devices:
            pcap_dir = "SUB_PCAPs/" + str(delta_time) + "/" + device
            pcap_list = os.listdir(pcap_dir)
            feature_dir = "SUB_FEATUREs/" + str(delta_time) + "/" + device
            os.mkdir(feature_dir)
            for pcap_file in pcap_list:
                feature_file = str.split(pcap_file, ".")[0]
                feature_file = feature_file + ".txt"
                print("tshark -X lua_script:extract_feature.lua -r " + pcap_dir + "/" + pcap_file + " > " + 
                    feature_dir + "/" + feature_file + " -q")
                os.system("tshark -X lua_script:extract_feature.lua -r " + pcap_dir + "/" + pcap_file + " > " + 
                    feature_dir + "/" + feature_file + " -q")
