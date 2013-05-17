-- Copyright (c)2011, Robert G. Jakabosky <bobby@sharedrealm.com>. All rights reserved.

local lexer = require("lludp.lexer")
local Token = lexer.Token
local TokenNames = lexer.TokenNames

local io_write = io.write
local format = string.format
local tinsert = table.insert
local pcall = pcall
local error = error
local tonumber = tonumber

local lex
local cur_token = nil
local cur_token_str = nil

local function get_token(skip_tokens)
	local token = lex.get_token()
	if token ~= nil then
		cur_token = token[1]
		cur_token_str = token[2]
	end
	return token
end

local function run_parser(parser)
	local state = parser.init()
	local skip_tokens = parser.skip_tokens
	if skip_tokens == nil then skip_tokens = {} end
	while get_token() do
		-- check what the parser is expecting next.
		if state.expect and not skip_tokens[cur_token] then
			-- check expected type
			if state.expect ~= cur_token then
				error(format("state.expected token '%s' instead of '%s'",
					TokenNames[state.expect], TokenNames[cur_token]))
			end
			-- reset expect field
			state.expect = nil
		end
		if state.expect_str and not skip_tokens[cur_token] then
			-- check expected string
			if state.expect_str ~= cur_token_str then
				error(format("state.expected token '%s' instead of '%s'",
					state.expect_str, cur_token_str))
			end
			-- reset expect_str field
			state.expect_str = nil
		end
		-- get handler function for current token.
		local f = parser[cur_token]
		if f ~= nil then
			local ret = f(state)
			if ret then
				-- praser finished.
				return ret
			end
		elseif parser.unhandled_error then
			error(format("unhandled token '%s' when paring '%s'\n", cur_token_str, parser.name))
		end
	end
	return parser.eof(state)
end

-- Known variable types and there fixed length.
--   length == -1, requires a number after the type that is the length of count field
--   length == -2, requires a number after the type that is the fixed variable length.
local VariableTypes = {
Null = 0,
Fixed = -2,
Variable = -1,
U8 = 1,
U16 = 2,
U32 = 4,
U64 = 8,
S8 = 1,
S16 = 2,
S32 = 4,
S64 = 8,
F32 = 4,
F64 = 8,
LLVector3 = 12,
LLVector3d = 24,
LLVector4 = 16,
LLQuaternion = 12,
LLUUID = 16,
BOOL = 1,
IPADDR = 4,
IPPORT = 2,
}

--
-- Variable parser
--
local variable_parser = {
name = "variable",
unhandled_error = false,
skip_tokens = {[Token.EOL] = true},
init = function()
	return {
		name = "<MISSING VARIABLE NAME>",
		type = "Null",
		has_count = false,
		length = 0,
		expect = Token.IDENTIFIER,
		expect_field = "name",
		required = 2
	}
end,
[Token.IDENTIFIER] 	= function(state)
	if state.expect_field == "name" then
		state.name = cur_token_str
		state.expect = Token.IDENTIFIER
		state.expect_field = "type"
		state.required = state.required - 1
	elseif state.expect_field == "type" then
		state.type = cur_token_str
		state.length = VariableTypes[state.type]
		if state.length == nil then
			error("Unknown variable type: " .. cur_token_str)
		elseif state.length == -1 or state.length == -2 then
			state.expect = Token.NUMBER
		else
			state.required = state.required - 1
		end
	else
		error(format("unhandled variable identifier: %s\n",cur_token_str))
	end
	return nil
end,
[Token.NUMBER]			= function(state)
	if state.expect_field == "type" then
		if state.length == -1 then
			-- variable field length uses embedded count field
			state.has_count = true
			state.count_length = tonumber(cur_token_str)
			state.length = nil
		elseif state.length == -2 then
			-- fixed field length
			state.length = tonumber(cur_token_str)
		end
		state.required = state.required - 1
	else
		error(format("unhandled variable number: %s\n",cur_token_str))
	end
	return nil
end,
["{"]		= function(state)
	error("sub block not allowed in variable block")
end,
["}"]		= function(state)
	if state.required > 0 then
		error("missing " .. state.required .. " fields")
	end
	-- clean state.
	state.required = nil
	state.expect = nil
	state.expect_field = nil
	return state
end,
eof = function(state)
	error("missing '}' token at end of variable: " .. state.name)
end,
}

-- Block Quantities
local BlockQuantity = {
Single = 1,
Variable = -1,
Multiple = -2,
}

--
-- Block parser
--
local block_parser = {
name = "block",
unhandled_error = false,
skip_tokens = {[Token.EOL] = true},
init = function()
	return {
		name = "<MISSING BLOCK NAME>",
		quantity = "Single",
		count = 0,
		min_length = 0,
		fixed_length = true,
		expect = Token.IDENTIFIER,
		expect_field = "name",
		required = 2,
		comments = {},
	}
end,
[Token.EOL] = function(state)
	if #state.comments > 0 and state.last_variable ~= nil then
		-- add pre-comments to last parsed variable.
		state.last_variable.comments = state.comments
		state.comments = {}
	end
	state.last_variable = nil
end,
[Token.COMMENT] = function(state)
	-- eol comment.
	if state.last_variable then
		state.last_variable.eol_comment = cur_token_str
	else
		state.comments[#state.comments + 1] = cur_token_str
	end
	return nil
end,
[Token.IDENTIFIER] 	= function(state)
	if state.expect_field == "name" then
		state.name = cur_token_str
		state.expect = Token.IDENTIFIER
		state.expect_field = "quantity"
		state.required = state.required - 1
	elseif state.expect_field == "quantity" then
		state.quantity = cur_token_str
		state.count = BlockQuantity[cur_token_str]
		if state.count == nil then
			error("Unknown block quantity: " .. cur_token_str)
		elseif state.count == -2 then
			state.expect_field = "count"
			state.expect = Token.NUMBER
		else
			if state.count == -1 then
				state.has_count = true
				state.count_length = 1
				state.count = nil
			end
			state.required = state.required - 1
		end
	else
		error(format("unhandled block identifier: %s\n",cur_token_str))
	end
	return nil
end,
[Token.NUMBER]			= function(state)
	if state.expect_field == "count" then
		state.count = tonumber(cur_token_str)
		state.required = state.required - 1
	else
		error(format("unhandled block number: %s\n",cur_token_str))
	end
	return nil
end,
["{"]		= function(state)
	local variable = run_parser(variable_parser)
	state.last_variable = variable
	tinsert(state,variable)
	-- add length of fixed length variables to minimal length of block.
	if variable.has_count then
		state.min_length = state.min_length + variable.count_length
		state.fixed_length = false
	else
		state.min_length = state.min_length + variable.length
	end
end,
["}"]		= function(state)
	if state.required > 0 then
		error("missing " .. state.required .. " fields")
	end
	-- clean state.
	state.required = nil
	state.expect = nil
	state.expect_field = nil
	return state
end,
eof = function(state)
	error("missing '}' token at end of block: " .. state.name)
end,
}

--
-- Message parser
--
local message_parser = {
name = "message",
unhandled_error = false,
skip_tokens = {[Token.EOL] = true},
init = function()
	-- create state
	return {
		name = "<MISSING MESSAGE NAME>",
		expect = Token.IDENTIFIER,
		expect_field = "name",
		fixed_length = true,
		min_length = 0,
		required = 5,
	}
end,
[Token.COMMENT] = function(state)
	return nil
end,
[Token.IDENTIFIER] 	= function(state)
	if state.expect_field == "name" then
		state.name = cur_token_str
		state.expect = Token.IDENTIFIER
		state.expect_field = "frequency"
		state.required = state.required - 1
	elseif state.expect_field == "frequency" then
		state.frequency = cur_token_str
		state.expect = Token.NUMBER
		state.required = state.required - 1
	elseif state.expect_field == "trust" then
		state.trust = cur_token_str
		state.expect = Token.IDENTIFIER
		state.expect_field = "compression"
		state.required = state.required - 1
	elseif state.expect_field == "compression" then
		state.compression = cur_token_str
		state.required = state.required - 1
	else
		error(format("unhandled message identifier: %s\n",cur_token_str))
	end
	return nil
end,
[Token.NUMBER]			= function(state)
	if state.expect_field == "frequency" then
		state.number = tonumber(cur_token_str)
		state.expect = Token.IDENTIFIER
		state.expect_field = "trust"
		state.required = state.required - 1
		-- create true message id from frequency and message number
		local freq = state.frequency
		if freq == "High" then
			-- High is already correct.
			state.id = state.number
			state.id_length = 1
		elseif freq == "Medium" then
			state.id = tonumber("0xFF" .. format("%02X", state.number))
			state.id_length = 2
		elseif freq == "Low" then
			state.id = tonumber("0xFFFF" .. format("%04X", state.number))
			state.id_length = 4
		else
			-- Fixed is already correct.
			state.id = state.number
			state.id_length = 4
		end
	else
		error(format("unhandled message number: %s\n",cur_token_str))
	end
	return nil
end,
["{"]		= function(state)
	local block = run_parser(block_parser)
	tinsert(state,block)
	-- add min length of block to minimal length of message
	local min_length = block.min_length
	if block.has_count then
		-- add one byte for the block count
		min_length = min_length + 1
		state.fixed_length = false
	else
		-- if block is not fixed length then message can't be fixed length.
		if not block.fixed_length then
			state.fixed_length = false
		end
		min_length = min_length * block.count
	end
	state.min_length = state.min_length + min_length
end,
["}"]		= function(state)
	if state.required > 0 then
		error("missing " .. state.required .. " fields")
	end
	-- clean state.
	state.required = nil
	state.expect = nil
	state.expect_field = nil
	return state
end,
eof = function(state)
	error("missing '}' token at end of message: " .. state.name)
end,
}

--
-- Template file parser
--
local template_parser = {
name = "message_template",
unhandled_error = false,
init = function()
	return {
		version = 0,
		msg_count = 0,
		msgs = {},
		msgs_file_order = {},
		comments = {},
	}
end,
[Token.COMMENT] = function(state)
	state.comments[#state.comments + 1] = cur_token_str
	return nil
end,
[Token.IDENTIFIER] 	= function(state)
	-- handle version
	if cur_token_str == "version" then
		state.expect = Token.NUMBER
		state.last_ident = cur_token_str
	else
		error(format("unknown template identifier: %s\n",cur_token_str))
	end
	return nil
end,
[Token.NUMBER]			= function(state)
	-- handle version number
	if state.last_ident == "version" then
		state.last_ident = nil
		state.version = tonumber(cur_token_str)
		-- check version number
		if state.version ~= 2 then
			error("invalid verion: " .. state.version)
		end
	else
		error(format("unhandled template number: %s\n",cur_token_str))
	end
	return nil
end,
["{"]		= function(state)
	local message = run_parser(message_parser)
	message.comments = state.comments
	state.comments = {}
	state.msg_count = state.msg_count + 1
	state.msgs[message.id] = message
	state.msgs_file_order[#state.msgs_file_order + 1] = message
end,
["}"]		= function(state)
	error(format("unhandled '%s' token",cur_token_str))
end,
eof = function(state)
	return state
end,
}

module('lludp.message_template')

function parse(file, quiet)
	-- create lexer
	local status, ret = pcall(lexer.new,file)
	if not status then
		ret = format("LLUDP: Failed parse file into tokens: %s\n%s\n", file, ret)
		error(ret, 0)
		return nil
	end
	lex = ret
	-- parse template file
	local status, ret = pcall(run_parser,template_parser)
	if not status then
		ret = format("LLUDP: Failed parsing on line %s:%d: '%s'\n%s\n",
			file, lexer.get_line_number(), lexer.get_line(), ret)
		error(ret, 0)
		return nil
	end
	if not quiet then
		io_write("finished parsing: " .. file .. "\n")
	end
	-- return list of messages parsed from file.
	return ret
end

