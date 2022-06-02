local getMAC = Field.new("eth.src")

local client_mac = {}     -- 原 PCAP 文件中包含的源 MAC 地址
client_mac["2a:77:e6:98:aa:02"] = true -- 192.168.137.174
client_mac["64:a2:00:e5:ed:e9"] = true -- 192.168.137.66
client_mac["18:3e:ef:d2:76:a3"] = true -- 192.168.137.244
client_mac["62:9a:a9:2d:46:95"] = true -- 192.168.137.193
client_mac["00:0a:f5:68:66:77"] = true -- 192.168.137.42
client_mac["24:a2:e1:23:4c:3c"] = true -- 192.168.137.240


local mac_pcap = {} -- 每个源 MAC 对应的 PCAP 文件的索引表

do
    local function packet_listener()
        local tap = Listener.new("frame", "ip")
        -- frame是监听器的名称，tcp是wireshark过滤器规则

        function tap.reset()
            print("tap reset")
        end

        function tap.packet(pinfo, tvb)

            local mac = tostring( getMAC() )
            
            if( client_mac[mac] ) then
                if( mac_pcap[mac] ) then
                    mac_pcap[mac]:dump_current()
                else
                    local pcap_file = mac..".pcap"
                    print( pcap_file )
                    mac_pcap[mac] = Dumper.new(pcap_file)
                    mac_pcap[mac]:dump_current()
                end
            end

        end

        function tap.draw()
            -- 结束执行
        end
    end
       -- 监听报文
    packet_listener()
       -- tcpStreamTable =nil
end