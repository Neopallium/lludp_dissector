--[[
BSD-Licensed:
Copyright (c)2011, Robert G. Jakabosky <bobby@sharedrealm.com>. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

THIS SOFTWARE IS PROVIDED BY "Robert G. Jakabosky" ''AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL "Robert G. Jakabosky" OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

]]

dofile("llmessage.lua")

-- cache globals to local for speed.
local str_format=string.format

-- test if ByteArray only has printable ASCII character and ends with '\0'
local allowed_special = {
	[0] = true, -- null
	[9] = true, -- tab
	[10] = true, -- new line
	[13] = true, -- carriage return
}
local function is_string(bytes)
	local c
	local max = bytes:len() - 1
	for i=0,max do
		c = bytes:get_index(i)
		if c >= 127 then -- not ascii character
			return false
		elseif c < 32 then  -- control character range
			if not allowed_special[c] then
				-- control characters between NULL and Space
				return false
			elseif c == 0 and i < max then
				-- null byte only allowed at end.
				return false
			end
		end
	end
	return true
end

-- lludp protocol example
-- declare our protocol
local lludp_proto = Proto("lludp","LLUDP","LindenLabs UDP Protocol")

-- setup preferences
lludp_proto.prefs["template_file"] =
	Pref.string("Message template file", "message_template.msg", "Message template file")
lludp_proto.prefs["udp_port_start"] =
	Pref.string("UDP port range start", "13000", "First UDP port to decode as this protocol")
lludp_proto.prefs["udp_port_end"] =
	Pref.string("UDP port range end", "13050", "Last UDP port to decode as this protocol")
-- current preferences settings.
local current_settings = {
template_file = "",
udp_port_start = -1,
udp_port_end = -1,
}
-- current list of parsed messages.
local message_details = nil

-- setup protocol fields.
lludp_proto.fields = {}
local fds = lludp_proto.fields
fds.flags = ProtoField.uint8("lludp.flags", "Flags", base.HEX, nil, 0xFF)
fds.flags_zero = ProtoField.uint8("lludp.flags.zero", "Zero", base.HEX, nil, 0x80)
fds.flags_reliable = ProtoField.uint8("lludp.flags.rel", "Reliable", base.HEX, nil, 0x40)
fds.flags_resent = ProtoField.uint8("lludp.flags.res", "Resent", base.HEX, nil, 0x20)
fds.flags_ack = ProtoField.uint8("lludp.flags.ack", "Ack", base.HEX, nil, 0x10)
fds.sequence = ProtoField.uint32("lludp.sequence", "Sequence", base.DEC)
fds.extra_len = ProtoField.uint8("lludp.extra_len", "Extra length", base.DEC)
fds.extra_bytes = ProtoField.bytes("lludp.extra_bytes", "Extra header", base.HEX)
fds.msg_id = ProtoField.uint32("lludp.msg.id", "Message ID", base.HEX)
fds.msg_name = ProtoField.bytes("lludp.msg.name", "Message name")
fds.msg = ProtoField.bytes("lludp.msg", "Message body", base.HEX)
fds.acks_count = ProtoField.uint8("lludp.acks_count", "Acks count", base.DEC)
fds.acks = ProtoField.uint32("lludp.acks", "Acks", base.DEC)
fds.block_count = ProtoField.uint8("lludp.block_count", "Block count", base.DEC)
fds.block = ProtoField.bytes("lludp.block", "Block", base.HEX)
fds.var_fixed = ProtoField.bytes("lludp.var.fixed", "Fixed blob", base.HEX)
fds.var_variable = ProtoField.bytes("lludp.var.variable", "Variable blob", base.HEX)
fds.var_string = ProtoField.stringz("lludp.var.string", "String")
fds.var_u8 = ProtoField.uint8("lludp.var.u8", "U8", base.DEC)
fds.var_u16 = ProtoField.uint16("lludp.var.u16", "U16", base.DEC)
fds.var_u32 = ProtoField.uint32("lludp.var.u32", "U32", base.DEC)
fds.var_u64 = ProtoField.uint64("lludp.var.u64", "U64", base.DEC)
fds.var_s8 = ProtoField.int8("lludp.var.s8", "S8", base.DEC)
fds.var_s16 = ProtoField.int16("lludp.var.s16", "S16", base.DEC)
fds.var_s32 = ProtoField.int32("lludp.var.s32", "S32", base.DEC)
fds.var_s64 = ProtoField.int64("lludp.var.s64", "S64", base.DEC)
fds.var_f32 = ProtoField.float("lludp.var.f32", "F32", base.DEC)
fds.var_f64 = ProtoField.double("lludp.var.f64", "F64", base.DEC)
fds.var_llvector3 = ProtoField.bytes("lludp.var.llvector3", "LLVector3", base.HEX)
fds.var_llvector3d = ProtoField.bytes("lludp.var.llvector3d", "LLVector3d", base.HEX)
fds.var_llvector4 = ProtoField.bytes("lludp.var.llvector4", "LLVector4", base.HEX)
fds.var_llquaternion = ProtoField.bytes("lludp.var.llquaternion", "LLQuaternion", base.HEX)
fds.var_lluuid = ProtoField.bytes("lludp.var.lluuid", "LLUUID", base.HEX)
fds.var_bool = ProtoField.uint8("lludp.var.bool", "BOOL", base.DEC)
fds.var_ipaddr = ProtoField.ipv4("lludp.var.ipaddr", "IPADDR", base.DEC)
fds.var_ipport = ProtoField.uint16("lludp.var.ipport", "IPPORT", base.DEC)
-- variable type handlers.
local variable_handlers = {
Fixed = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_fixed, rang)
	if len <= 4 then
		ti:set_text(str_format("%s: 0x%08x",var.name, rang:uint()))
	else
		ti:set_text(str_format("%s: length=%d, Blob:%s", var.name, len, tostring(rang)))
	end
end,
Variable = function(block_tree, buffer, offset, len, var)
	local is_data = false
	-- try to guess if this field is text.
	if var.name:find("Data") then
		-- this is a data find.
		is_data = true
	end
	local str_rang = buffer(offset + var.count_length, len - var.count_length)
	local bytes = str_rang:bytes()
	if not is_data and is_string(bytes) then
		local str = str_rang:string()
		local ti = block_tree:add(fds.var_string, buffer(offset, len))
		ti:set_text(str_format("%s: %s", var.name, str))
	else
		local rang = buffer(offset, len)
		local ti = block_tree:add_le(fds.var_variable, rang)
		if len <= 4 then
			ti:set_text(str_format("%s: 0x%08x",var.name, rang:uint()))
		else
			ti:set_text(str_format("%s: length=%d, Blob:%s", var.name, len, tostring(rang)))
		end
	end
end,
U8 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_u8, rang)
	ti:set_text(str_format("%s: %d", var.name, rang:le_uint()))
end,
U16 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_u16, rang)
	ti:set_text(str_format("%s: %d", var.name, rang:le_uint()))
end,
U32 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_u32, rang)
	ti:set_text(str_format("%s: %d", var.name, rang:le_uint()))
end,
U64 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_u64, rang)
	ti:set_text(str_format("%s: 0x%s",var.name, tostring(rang)))
end,
S8 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_s8, rang)
	local num = rang:le_uint()
	if num > 127 then num = num - 256 end
	ti:set_text(str_format("%s: %d",var.name, num))
end,
S16 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_s16, rang)
	local num = rang:le_uint()
	if num > 32768 then num = num - 65536 end
	ti:set_text(str_format("%s: %d",var.name, num))
end,
S32 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_s32, rang)
	local num = rang:le_uint()
	if num > 2147483648 then num = num - 4294967296 end
	ti:set_text(str_format("%s: %d",var.name, num))
end,
S64 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_s64, rang)
	ti:set_text(str_format("%s: 0x%s",var.name, tostring(rang)))
end,
F32 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_f32, rang)
	ti:set_text(str_format("%s: %f", var.name, rang:le_float()))
end,
F64 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_f64, rang)
	ti:set_text(str_format("%s: %f", var.name, rang:le_float()))
end,
LLVector3 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_llvector3, rang)
	-- parse LLVector3
	local x,y,z
	x = buffer(offset + 0,4):le_float()
	y = buffer(offset + 4,4):le_float()
	z = buffer(offset + 8,4):le_float()
	-- display
	ti:set_text(str_format("%s: <%f,%f,%f>", var.name, x, y, z))
end,
LLVector3d = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_llvector3d, rang)
	-- parse LLVector3d
	local x,y,z
	x = buffer(offset + 0,8):le_float()
	y = buffer(offset + 8,8):le_float()
	z = buffer(offset + 16,8):le_float()
	-- display
	ti:set_text(str_format("%s: <%f,%f,%f>", var.name, x, y, z))
end,
LLVector4 = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_llvector4, rang)
	-- parse LLVector4
	local x,y,z,s
	x = buffer(offset + 0,4):le_float()
	y = buffer(offset + 4,4):le_float()
	z = buffer(offset + 8,4):le_float()
	s = buffer(offset + 12,4):le_float()
	-- display
	ti:set_text(str_format("%s: <%f,%f,%f,%f>", var.name, x, y, z, s))
end,
LLQuaternion = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_llquaternion, rang)
	-- parse LLQuaternion
	local x,y,z,w
	x = buffer(offset + 0,4):le_float()
	y = buffer(offset + 4,4):le_float()
	z = buffer(offset + 8,4):le_float()
	-- calculate W
	w = 1 - (x * x) - (y * y) - (z * z)
	if w > 0 then
		w = math.sqrt(w)
	else
		w = 0
	end
	-- display
	ti:set_text(str_format("%s: <%f,%f,%f,%f>", var.name, x, y, z, w))
end,
LLUUID = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_lluuid, rang)
	local str = tostring(rang)
	str = str:sub(1,8) .. '-' ..
		str:sub(9,12) .. '-' .. str:sub(13,16) .. '-' ..
		str:sub(17,20) .. '-' .. str:sub(21)
	ti:set_text(str_format("%s: %s", var.name, str))
end,
BOOL = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add_le(fds.var_bool, rang)
	local val = "false"
	if rang:le_uint() > 0 then
		val = "true"
	end
	ti:set_text(str_format("%s: %s", var.name, val))
end,
IPADDR = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add(fds.var_ipaddr, rang)
	ti:set_text(str_format("%s: %s", var.name, tostring(rang:ipv4())))
end,
IPPORT = function(block_tree, buffer, offset, len, var)
	local rang = buffer(offset, len)
	local ti = block_tree:add(fds.var_ipport, rang)
	ti:set_text(str_format("%s: %d", var.name, rang:uint()))
end,
}

-- un-register lludp to handle udp port range
local function unregister_udp_port_range(start_port, end_port)
	if not start_port or start_port <= 0 or not end_port or end_port <= 0 then
		return
	end
  udp_port_table = DissectorTable.get("udp.port")
  for port = start_port,end_port do
    udp_port_table:remove(port,lludp_proto)
  end
end

-- register lludp to handle udp port range
local function register_udp_port_range(start_port, end_port)
	if not start_port or start_port <= 0 or not end_port or end_port <= 0 then
		return
	end
	udp_port_table = DissectorTable.get("udp.port")
	for port = start_port,end_port do
		udp_port_table:add(port,lludp_proto)
	end
end

-- handle preferences changes.
function lludp_proto.init(arg1, arg2)
	local old_start, old_end
	local new_start, new_end
	-- check if preferences have changed.
	for pref_name,old_v in pairs(current_settings) do
		local new_v = lludp_proto.prefs[pref_name]
		if new_v ~= old_v then
			if pref_name == "template_file" then
				-- load & parse message_template.msg file.
				local file = new_v
				if file and file:len() > 0 then
					local new_details = parse_template(file)
					if new_details then
						message_details = new_details
					end
				end
			elseif pref_name == "udp_port_start" then
				old_start = old_v
				new_start = new_v
			elseif pref_name == "udp_port_end" then
				old_end = old_v
				new_end = new_v
			end
			-- save new value.
			current_settings[pref_name] = new_v
		end
	end
	-- un-register old port range
	if old_start and old_end then
		unregister_udp_port_range(tonumber(old_start), tonumber(old_end))
	end
	-- register new port range.
	if new_start and new_end then
		register_udp_port_range(tonumber(new_start), tonumber(new_end))
	end
end

-- parse flag bits.
local FLAG_ZER = 4
local FLAG_REL = 3
local FLAG_RES = 2
local FLAG_ACK = 1
local flag_names = {"ACK", "RES", "REL", "ZER"}
local bits_lookup = {
	{},
	{1},
	{2},
	{2,1},
	{3},
	{3,1},
	{3,2},
	{3,2,1},
	{4},
	{4,1},
	{4,2},
	{4,2,1},
	{4,3},
	{4,3,1},
	{4,3,2},
	{4,3,2,1},
}
local function parse_flags(flags)
	flags = (flags / 16) + 1
	local bit_list = bits_lookup[flags]
	local bits = {}
	local names = ""
	for _, bit in ipairs(bit_list) do
		bits[bit] = true
		if names:len() > 0 then
			names = names .. ", "
		end
		names = names .. flag_names[bit]
	end
	return bits, names
end

local function grow_buff(buff, size)
	local old_size = buff:len()
	if old_size > size then return end
	-- buffer needs to grow
	buff:set_size(size)
	-- fill new space with zeros
	for i = old_size,size-1 do
		buff:set_index(i, 0)
	end
end

local function zero_decode(zero_buf)
	local out_buf = ByteArray.new()
	local zero_off = 0
	local zero_len = zero_buf:len()
	local out_size = 0
	local out_off = 0
	local b
	-- pre-allocate
	grow_buff(out_buf, zero_len)
	out_size = zero_len
	-- zero expand
	repeat
		b = zero_buf:get_index(zero_off)
		if b == 0 then
			-- get zero count
			local count = zero_buf:get_index(zero_off + 1)
			if count == 0 then count = 255 end
			out_off = out_off + count
			-- fill zeros
			if out_off > out_size then
				out_size = out_off + 128
				grow_buff(out_buf, out_size)
			end
			zero_off = zero_off + 2
		else
			if out_off >= out_size then
				out_size = out_off + (zero_len - zero_off) + 4
				grow_buff(out_buf, out_size)
			end
			-- copy non-zero bytes.
			out_buf:set_index(out_off,b)
			zero_off = zero_off + 1
			out_off = out_off + 1
		end
	until zero_off == zero_len
	-- truncate to real size.
	out_buf:set_size(out_off)

	return out_buf:tvb("Decompressed Data")
end

local function parse_msg_id(buff)
	local b = buff:get_index(0)
	local msg_id = b
	local msg_id_len = 1
	if b == 255 then
		b = buff:get_index(1)
		msg_id = msg_id * 256 + b
		msg_id_len = 2
		if b == 255 then
			b = buff:get_index(2)
			msg_id = msg_id * 256 + b
			b = buff:get_index(3)
			msg_id = msg_id * 256 + b
			msg_id_len = 4
		end
	end
	return msg_id, msg_id_len
end

-- get message name.
local function get_msg_name(msg_id)
	-- check that we have message details
	if message_details == nil then
		return str_format("0x%08x", msg_id)
	end
	-- find message name from id.
	local msg = message_details.msgs[msg_id]
	-- Invalid message id
	if msg == nil then
		return str_format("0x%08x", msg_id)
	end
	return msg.name
end

-- calculate length a block.
local function get_block_length(msg_buffer, start_offset, block)
	-- check if bock is fixed length.
	if block.fixed_length then
		return block.min_length
	end
	-- parse block's variables to calculate total block length.
	local offset = start_offset
	local rang
	for _,var in ipairs(block) do
		local len = 0
		if var.has_count then
			-- variable with length bytes.
			len = var.count_length
			--print(var.name, offset, ", len:", len)
			rang = msg_buffer(offset, len)
			len = len + rang:le_uint()
			--print(var.name, var.count_length, ", total:", len)
		else
			-- fixed length variable
			len = var.length
			--print(var.name, ", total:", len)
		end
		offset = offset + len
	end
	return (offset - start_offset)
end

-- build block tree
local function build_block_tree(msg_buffer, block_tree, start_offset, block)
	local offset = start_offset
	local rang
	-- parse block's variables
	for _,var in ipairs(block) do
		local len = 0
		if var.has_count then
			-- variable with length bytes.
			len = var.count_length
			rang = msg_buffer(offset, len)
			len = len + rang:le_uint()
		else
			-- fixed length variable
			len = var.length
		end
		-- get variable's type field.
		local handler = variable_handlers[var.type]
		-- parse variable.
		if handler then
			handler(block_tree, msg_buffer, offset, len, var)
		end
		offset = offset + len
	end
	return (offset - start_offset)
end

-- buid message tree
local function build_msg_tree(msg_buffer, msg_tree, msg_id)
	local offset = 0
	local rang
	-- check that we have message details
	if message_details == nil then
		msg_tree:set_text(str_format("Message Id: 0x%08x", msg_id))
		return nil
	end
	-- find message name from id.
	local msg = message_details.msgs[msg_id]
	-- Invalid message id
	if msg == nil then
		msg = str_format("Invalid message id: 0x%08x", msg_id)
		msg_tree:add_expert_info(PI_MALFORMED, PI_ERROR, msg)
		msg_tree:set_text(msg)
		return nil
	end
	-- skip message id bytes.
	offset = msg.id_length
	-- set message name.
	msg_tree:set_text(msg.name .. ":")
	-- proccess message blocks
	for _,block in ipairs(msg) do
		local count = block.count
		if count == nil then
			-- parse count byte.
			rang = msg_buffer(offset,1)
			count = rang:uint()
  		msg_tree:add(fds.block_count,rang)
			offset = offset + 1
		end
		-- print("block name: ", block.name, count)
		for n=1,count do
			local block_len = get_block_length(msg_buffer, offset, block)
			-- parse block
			rang = msg_buffer(offset, block_len)
			local block_tree = msg_tree:add(fds.block,rang)
			if count > 1 then
				block_tree:set_text(str_format("%s: %d of %d",block.name,n,count))
			else
				block_tree:set_text(block.name)
			end
			-- parse block variables.
			build_block_tree(msg_buffer, block_tree, offset, block)
			offset = offset + block_len
		end
	end
	return msg.name
end

-- packet dissector
function lludp_proto.dissector(buffer,pinfo,tree)
	local rang,offset
	pinfo.cols.protocol = "LLUDP"
	local lludp_tree = tree:add(lludp_proto,buffer(),"Linden UDP Protocol")
	-- Flags byte.
	offset = 0
	rang = buffer(offset,1)
	local flags = rang:uint()
	local flags_bits, flags_list = parse_flags(flags)
	flags_tree = lludp_tree:add(fds.flags, rang)
	flags_tree:set_text("Flags: " .. str_format('0x%02X (%s)', flags, flags_list))
	flags_tree:add(fds.flags_zero, rang)
	flags_tree:add(fds.flags_reliable, rang)
	flags_tree:add(fds.flags_resent, rang)
	flags_tree:add(fds.flags_ack, rang)
	offset = offset + 1
	-- Sequence number 4 bytes.
	rang = buffer(offset,4)
	local sequence = rang:uint()
	lludp_tree:add(fds.sequence, rang)
	offset = offset + 4
	-- Extra header length.
	rang = buffer(offset,1)
	local extra_length = rang:uint()
	lludp_tree:add(fds.extra_len,rang)
	offset = offset + 1
	-- Extra header data.
	if extra_length > 0 then
		rang = buffer(offset, extra_length)
		lludp_tree:add(fds.extra_bytes, rang)
		offset = offset + extra_length
	end
	-- Appended Acks. count
	local acks_bytes = 0
	local acks_count = 0
	if flags_bits[FLAG_ACK] then
		rang = buffer(buffer:len() - 1, 1)
		acks_count = rang:uint()
		acks_bytes = (acks_count * 4) + 1
	end
	-- Zero Decode
	local msg_len = (buffer:len() - acks_bytes) - offset
	if flags_bits[FLAG_ZER] then
		msg_buffer=zero_decode(buffer(offset,msg_len):bytes())
		msg_len = msg_buffer:len()
		offset = 0
	else
		msg_buffer = buffer(offset, msg_len):tvb()
		offset = 0
	end
	-- Message ID
	local msg_id, msg_id_len = -1, 4
	if msg_id_len > msg_len then
		msg_id_len = msg_len
	end
	msg_id, msg_id_len = parse_msg_id(msg_buffer(offset, msg_id_len):bytes())
	rang = msg_buffer(offset, msg_id_len)
	local msg_id_tree = lludp_tree:add(fds.msg_id, rang)
	local msg_name = get_msg_name(msg_id)
	if msg_name == nil then
		msg_id_tree:set_text(str_format("Message name: 0x%08x", msg_id))
	else
		msg_id_tree:set_text(str_format("Message name: %s",msg_name))
	end
	-- Message body.
	rang = msg_buffer(offset, msg_len)
	local msg_tree = lludp_tree:add(fds.msg, rang)
	build_msg_tree(msg_buffer, msg_tree, msg_id)
	-- Appended Acks. list.
	if flags_bits[FLAG_ACK] then
		local acks_off = buffer:len()
		rang = buffer(acks_off - 1, 1)
		acks_off = acks_off - acks_bytes
		local acks_tree = lludp_tree:add(fds.acks_count, rang)
		for i = 1,acks_count do
			rang = buffer(acks_off,4)
			acks_tree:add(fds.acks, rang)
			acks_off = acks_off + 4
		end
	end
	-- Info column
	pinfo.cols.info = str_format('[%s] Seq=%u Type=%s', flags_list, sequence, msg_name)
end

-- register lludp to handle udp ports 9000-9003
register_udp_port_range(9000,9003)

