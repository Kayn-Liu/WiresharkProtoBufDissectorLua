--get an existed protobuf dissector in Wireshark
local protobuf_dissector = Dissector.get("protobuf");

--Proto class can be used as a dissector of Protobuf
--but in my case, I simply used it as a dummy to register preferences
--when I actually need to dissect protobuf data, I call the above dissector
--@param myProto name to be displayed
--@param "My Proto" desc
local my_proto = Proto("MyProto", "My Proto");

---define a callback function Wireshark will call upon each packet
---@param tvb table a special class to handle the binary buffer object
---@param pinfo table an object to store packet info
---@param tree table display hierarchy tree on Wireshark GUI
-- The TCP dissector will parse tvb as format:
-- [Header][Message Data]
-- Header: [2 bytes length]
my_proto.dissector = function(tvb, pinfo, tree)
    if tvb:captured_len() == 0 then return end;
    if pinfo.port_type == 2 then --TCP
        pinfo.columns.columns.protocol:set(my_proto.name);
        --create a sub-node as a root to display my own proto data
        local subtree = tree:add(my_proto, tvb());
        local offset = 0;
        local length = tvb(0, 2):le_uint(); --[2 bytes length]
        local data_len = length - 2; --calculate the actual data length for later use
        offset = offset + 2;
        pinfo.private["pb_msg_type"] = "message,myProto.Message";
        pcall(Dissector.call, protobuf_dissector, tvb(offset, data_len), pinfo, subtree);
    end
end

-- register my_proto object to WireShark tcp port
-- if you already know your port, you can put it down
-- else you can just put down 0
-- you can later register the port to this dissector int the "Decode As" menu
DissectorTable.get("tcp.port"):add(0, my_proto);