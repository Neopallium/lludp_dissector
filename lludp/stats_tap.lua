
local tap = require"lludp.tap"

local format = string.format

local stats_tap_mt = {}
stats_tap_mt.__index = stats_tap_mt

function stats_tap_mt:get_endpoint_acks(ep)
	local ep_acks = self.track_acks[ep]
	if not ep_acks then
		self.endpoint_count = self.endpoint_count + 1
		ep_acks = {}
		self.track_acks[ep] = ep_acks
	end
	return ep_acks
end

function stats_tap_mt:push_pending_ack(src, seq)
	local src_acks = self:get_endpoint_acks(src)
	if not src_acks[seq] then
		src_acks[seq] = 0
		self.pending_acks = self.pending_acks + 1
	end
end

function stats_tap_mt:process_acks(dst, acks)
	local dst_acks = self:get_endpoint_acks(dst)
	for ack in string.gmatch(acks, "%d+") do
		self.total_acks = self.total_acks + 1
		ack = tonumber(ack)
		local track_ack = dst_acks[ack]
		if not track_ack then
			self.invalid_acks = self.invalid_acks + 1
		elseif track_ack == 0 then
			dst_acks[ack] = 1
			self.pending_acks = self.pending_acks - 1
		else
			dst_acks[ack] = track_ack + 1
			self.extra_acks = self.extra_acks + 1
		end
	end
end

function stats_tap_mt:packet(pinfo, _, td)
	local src, dst
	if td then
		src = format("%s:%s",td.ip_src, td.uh_sport)
		dst = format("%s:%s",td.ip_dst, td.uh_dport)
	else
		src = "missing"
		dst = "missing"
	end
	-- count all LLUDP packets
	local msg = pinfo.private
	if not msg then
		return
	end
	self.count = self.count + 1

	-- count each message type
	local msg_count = self.message_counts[msg.name] or 0
	self.message_counts[msg.name] = msg_count + 1

	local flags = msg.flags or ""
	-- reliable
	if flags:find("REL") then
		self.reliable = self.reliable + 1
		-- add sequence # to pending acks list.
		local seq = tonumber(msg.sequence)
		self:push_pending_ack(src, seq)
	end
	-- resent
	if flags:find("RES") then
		self.resent = self.resent + 1
	end
	-- has acks
	if flags:find("ACK") then
		self.acks = self.acks + 1
	end
	-- process packet acks.  (including 'PacketAck' messages)
	local acks = msg.acks or ""
	if #acks > 0 then
		self:process_acks(dst, acks)
	end
	-- zero-encoded/non-zero-encoded
	if flags:find("ZER") then
		self.zero_count = self.zero_count + 1
		local saved = tonumber(msg.zero_saved)
		if saved <= 0 then
			self.zero_expanded = self.zero_expanded + 1
		end
		self.zero_saved = self.zero_saved + saved
	else
		self.non_zero_count = self.non_zero_count + 1
	end
end

function stats_tap_mt:draw()
	local msg_counts = {}
	for name, cnt in pairs(self.message_counts) do
		msg_counts[#msg_counts+1] = format("%s: %d\n", name, cnt)
	end
	local stats = format([[
LLUDP Packets: %d
Message type counts:
%s
Flags:
  Reliable: %d
  Resent: %d
  ACKs: %d
Zero stats:
  Encoded: %d, Non-encoded: %d
  Expanded: %d
  Bytes Saved: %d
Ack stats:
  Total acks: %d
  Pending acks: %d
  Invalid acks: %d
  Extra acks: %d
  Packet acks: %d
Endpoints: %d
]],
	self.count,
	table.concat(msg_counts,""),
	self.reliable,
	self.resent,
	self.acks,
	self.zero_count,
	self.non_zero_count,
	self.zero_expanded,
	self.zero_saved,
	self.total_acks,
	self.pending_acks,
	self.invalid_acks,
	self.extra_acks,
	self.message_counts.PacketAck or 0,
	self.endpoint_count
	)

	return stats
end

function stats_tap_mt:reset()
	self.endpoint_count = 0
	self.count = 0
	self.reliable = 0
	self.resent = 0
	self.acks = 0
	self.non_zero_count = 0
	self.zero_count = 0
	self.zero_expanded = 0
	self.zero_saved = 0

	self.message_counts = {}

	self.total_acks = 0
	self.pending_acks = 0
	self.invalid_acks = 0
	self.extra_acks = 0
	self.track_acks = {}
end

local function create_stats_tap()
	local stats_tap = setmetatable({}, stats_tap_mt)

	stats_tap:reset() -- initialize tap.
	return stats_tap, 'lludp', 'udp'
end

tap.register("LLUDP stats tap", create_stats_tap)

