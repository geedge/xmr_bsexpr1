local json = require("cjson")
local md5 = require("md5")
require "bit32"
local cj = json.new()

local getTcpStream = Field.new("tcp.stream")

-- frame
local getTime = Field.new("frame.time_relative")

-- ip/tcp info
local tcp = Field.new("tcp")
local tcpWs = Field.new("tcp.window_size")
local ipTtl = Field.new("ip.ttl")
local ipDf = Field.new( "ip.flags.df" )
local ipHdl = Field.new( "ip.hdr_len" )
local tcpHdl = Field.new( "tcp.hdr_len" )
local tcpOpts = Field.new("tcp.options")
local ipLen = Field.new("ip.len")
local ipId = Field.new("ip.id")
local ipVer = Field.new("ip.version")
local tcpAck = Field.new("tcp.ack_raw")
local tcpTSval = Field.new("tcp.options.timestamp.tsval")
local tcpTSecr = Field.new("tcp.options.timestamp.tsecr")
local tcpSPort = Field.new("tcp.srcport")


-- TCP原本的 tcp flags
local tfUrg = Field.new("tcp.flags.urg")
local tfAck = Field.new("tcp.flags.ack")
local tfPush = Field.new("tcp.flags.push")
local tfReset = Field.new("tcp.flags.reset")
local tfSyn = Field.new("tcp.flags.syn")
local tfFin = Field.new("tcp.flags.fin")

local getTcpPayload = Field.new("tcp.len")

local function getTcpFp(opt, tcpflags)

    -- print( pinfo.number )

    local tcp_opt_table = { [0] = "E", -- eol
        [1] = "N", -- nop
        [2] = "M", -- mss
        [3] = "W", -- ws
        [4] = "S", -- sack
        [5] = "K", -- sack_param
        [6] = "J",
        [7] = "F",
        [8] = "T", -- time
        [9] = "P",
        [10] = "R"
        -- ["22"] = "tfo"      -- tcp fast open
    }

    -- TCP fingerprint's format be like: 65535:64:1:60:M1460,S,T,N,W8:.
    local tcp_fp = tostring( tcpWs() )..":"
    tcp_fp = tcp_fp..tostring( ipTtl() )..":"
    tcp_fp = tcp_fp..tostring( bit32.rshift( bit32.band( ipDf().range:uint(), 0x40 ), 6) )..":"

    -- print( bit32.rshift( bit32.band( ipDf().range:uint(), 0x40 ), 6) )

    local ip_hdl = bit32.band( ipHdl().range:uint(), 0x0F) * 4
    local tcp_hdl = bit32.rshift( bit32.band( tcpHdl().range:uint(), 0xF0), 4 ) * 4
    tcp_fp = tcp_fp..tostring( ip_hdl + tcp_hdl )..":"

    local opts_byte = opt.range
    local opts_size = opt.range:len()
    local opts_str = ""
    local cur = 0

    while ( cur < opts_size ) do
        local opt_type = opts_byte:range( cur, 1 ):uint()

        if ( opt_type == 0 ) then -- eol
            opts_str = opts_str.."E,"
            break
        end
        
        local opt_size = 0
        if( cur + 1< opts_size ) then -- tcp options 的最后一个可能是 eol 也可能是 nop
            opt_size = opts_byte:range( cur + 1, 1 ):uint()
        end

        if( tcp_opt_table[opt_type] == nil ) then 
            opts_str = opts_str.."U," -- unknown
            cur = cur + opt_size
        else
            opts_str = opts_str..tcp_opt_table[opt_type]
            if ( opt_type == 2 or opt_type == 3) then
                opts_str = opts_str..tostring( opts_byte:range( cur + 2, opt_size - 2):uint() )
                cur = cur + opt_size
            elseif ( opt_type == 1 ) then
                cur = cur + 1
            else
                cur = cur + opt_size
            end
            opts_str = opts_str..","
        end
    end

    tcp_fp = tcp_fp..string.sub( opts_str, 1, -2 )..":"

    local odd = ""

    if ( string.sub( opts_str, -1, -1 ) == "E" ) then
        odd = odd.."p"
    end

    if ( ipId().range:uint() == 0 ) then
        odd = odd.."Z" -- 65535:64:1:64:M1460,N,W6,N,N,T,S,E:Z
    end

    if ( ip_hdl > 20 ) then
        odd = odd.."I"
    end

    local x_len = 0
    if ( bit32.rshift( bit32.band( ipVer().range:uint(), 0x40), 4) == 4 ) then
        x_len = ipLen().range:uint() - ip_hdl - tcp_hdl
    end

    if ( x_len > 0 ) then
        odd = odd.."D"
    end

    if ( string.sub( tcpflags, 1, 1 ) == "U" ) then
        odd = odd.."U"
    end

    if ( ( tcpflags == "....S." or tcpflags == ".A..S." ) and tcpAck().range:uint() ~= 0 ) then
        odd = odd.."A"
    end

    if ( tcpTSecr() ~= nil ) then
        if ( tcpflags == "....S." and tcpTSecr().range:uint() ~= 0 ) then
            odd = odd.."T"
        end
    end

    if ( odd == "" ) then
        odd = "."
    end

    tcp_fp = tcp_fp..odd

    -- print( tcp_fp )
    return tcp_fp
end

local function handle_tcp(pinfo)
    local rel_time = tostring( getTime() )
    local src_ip = tostring(pinfo.net_src)
    local dst_ip = tostring(pinfo.net_dst)

    -- 捕获时间、源IP、目的IP、IP-ID
    local to_be_print = rel_time.." "..src_ip.." "..dst_ip.." "..tostring( ipId().range:uint() )

    if( tfAck() ~= nil ) then
        local tcpflags = ""
        if( tostring(tfUrg()) == "1" ) then tcpflags = tcpflags.."U" else tcpflags = tcpflags.."." end
        if( tostring(tfAck()) == "1" ) then tcpflags = tcpflags.."A" else tcpflags = tcpflags.."." end
        if( tostring(tfPush()) == "1" ) then tcpflags = tcpflags.."P" else tcpflags = tcpflags.."." end
        if( tostring(tfReset()) == "1" ) then tcpflags = tcpflags.."R" else tcpflags = tcpflags.."." end
        if( tostring(tfSyn()) == "1" ) then tcpflags = tcpflags.."S" else tcpflags = tcpflags.."." end
        if( tostring(tfFin()) == "1" ) then tcpflags = tcpflags.."F" else tcpflags = tcpflags.."." end

        to_be_print = to_be_print.." "..tcpflags

        -- SYN 报文的 TCP/IP 指纹、TCP Time Stamp(Linux)、Source Port(XUN)
        if( tcpflags == "....S." ) then
            to_be_print = to_be_print.." "..getTcpFp(tcpOpts(), tcpflags)
            to_be_print = to_be_print.." "..tostring( tcpSPort() )
            if( tcpTSval() ~= nil ) then
                to_be_print = to_be_print.." "..tostring( tcpTSval().range:uint() )
            end
            -- to_be_print = to_be_print..tcpTSval()
        end
    end

    print( to_be_print )

end

do
    local function packet_listener()
        local tap = Listener.new("frame", "ip and !tcp.analysis.retransmission", false)

        function tap.reset()
            -- 开始执行
        end

        function tap.packet(pinfo, tvb)
            local time = tostring( getTime() )
            -- print( time )
            handle_tcp(pinfo)
        end

        function tap.draw()
            -- 结束执行
        end
    end

    packet_listener()
end