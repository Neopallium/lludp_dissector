-- Copyright (c) 2020, Robert G. Jakabosky <rjakabosky@sharedrealm.com> All rights reserved.

local io_lines = io.lines
local io_write = io.write
local pairs = pairs
local tonumber = tonumber
local tinsert = table.insert
local format = string.format

-- Token types.
local Token = {
NONE         = -1,
IDENTIFIER   = -2,
NUMBER       = -3,
COMMENT      = -6,
EOL          = -7,
["{"] = "{",
["}"] = "}",
}
local TokenNames = {}
for name,val in pairs(Token) do
	TokenNames[val] = name
end

-- parse line into array of tokens.
local function default_parse_tokens(line)
	local tokens = {}
	local comment = nil
	-- check for a comment on this line.
	local idx = line:find("//")
	if idx ~= nil then
		local text = line:sub(idx + 2)
		-- remove space from start of comment.
		while text:sub(1,1) == ' ' do
			text = text:sub(2)
		end
		comment = {Token.COMMENT, text}
		-- remove comment from line
		line = line:sub(1,idx - 1)
	end

	-- split line into tokens using white-space as token delimitator
	for tok in line:gmatch("%s?([^%s]+)") do
		local tok_type
		-- check for number
		if tonumber(tok) ~= nil then
			tok_type = Token.NUMBER
		elseif Token[tok] then
			-- token is same as type
			tok_type = Token[tok]
		else
			-- token is an identifier
			tok_type = Token.IDENTIFIER
		end
		tinsert(tokens,{tok_type,tok})
	end
	-- insert comment token.
	if comment ~= nil then
		tinsert(tokens,comment)
	end
	-- add token to mark the end of this line
	tinsert(tokens,{Token.EOL, ""})
	return tokens
end

local function new(file, parse_tokens)
	-- use the default line tokenizer if one is not provided
	parse_tokens = parse_tokens or default_parse_tokens
	-- next/current line code
	local line_num = 0
	local line = nil
	local next_line,next_state = io_lines(file)
	-- parse line tokens code
	local next_tokens = function ()
		local tokens
		repeat
			line_num = line_num + 1
			line = next_line(next_state)
			if line == nil then return nil end
			-- parse tokens on this line
			tokens = parse_tokens(line)
		until tokens ~= nil
		return tokens
	end
	local tokens = nil
	local idx = 0

	-- build lexer table.
	local lexer = {
	get_token = function ()
		-- return next token
		idx = idx + 1
		if tokens and tokens[idx] then
			return tokens[idx]
		end
		-- we need more tokens
		tokens = next_tokens()
		-- where there anymore tokens?
		if not tokens then return nil end
		-- return first token
		idx = 1
		return tokens[1]
	end,
	get_line_number = function() return line_num end,
	get_line = function() return line end
	}
	return lexer
end

local function dump(file)
	local lexer = new(file)
	local num = -1
	while true do
		local tok = lexer.get_token()
		if tok == nil then
			break
		end
		if num ~= lexer.get_line_number() then
			num = lexer.get_line_number()
			io_write("\n")
			io_write(format("%d: ",num))
		end
		io_write(format("%s ",tok[2]))
	end
	io_write("\n")
end

return {
	-- export Token & TokenNames tables
	Token = Token,
	TokenNames = TokenNames,

	new = new,
	dump = dump,
}
