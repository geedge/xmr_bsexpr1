local getMAC = Field.new("eth.src")

local client_mac = {}     -- 原 PCAP 文件中包含的源 MAC 地址
client_mac["00:0c:29:24:19:71"] = true -- 192.168.47.11
client_mac["00:0c:29:22:ea:75"] = true -- 192.168.47.10
client_mac["00:0c:29:60:d3:de"] = true -- 192.168.47.7
client_mac["00:0c:29:83:95:e7"] = true -- 192.168.47.15

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
            -- print( mac )
            
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