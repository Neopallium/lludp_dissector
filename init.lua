-- register http to handle tcp ports 8000-8010 and 9000
do
  local tcp_port_table = DissectorTable.get("tcp.port")
  local http_dissector = tcp_port_table:get_dissector(80)
  for port = 8000,8010 do
    tcp_port_table:add(port,http_dissector)
  end
  tcp_port_table:add(9000,http_dissector)
end
 
-- Load lludp protocol dissector.
require("lludp.dissector")

