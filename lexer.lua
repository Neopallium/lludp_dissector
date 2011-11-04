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

-- Token types.
Token = {
NONE         = -1,
IDENTIFIER   = -2,
NUMBER       = -3,
COMMENT      = -6,
EOL          = -7,
["{"] = "{",
["}"] = "}",
}
TokenNames = {
[-1] = "NONE",
[-2] = "IDENTIFIER",
[-3] = "NUMBER",
[-6] = "COMMENT",
[-7] = "EOL",
["{"] = "{",
["}"] = "}",
}

-- parse line into array of tokens.
local function default_parse_tokens(line)
	local tokens = {}
	local comment = nil
	-- check for a comment on this line.
	local idx = line:find("//")
	if idx ~= nil then
		comment = {Token.COMMENT, line:sub(idx)}
		-- remove comment from line
		line = line:sub(1,idx - 1)
	end

	-- split line into tokens using white-space as token delimitator
	for tok in line:gmatch("%s?([^%s]+)") do
		local tok_type = Token.NONE
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
		table.insert(tokens,{tok_type,tok})
	end
	-- insert comment token.
	if comment ~= nil then
		table.insert(tokens,comment)
	end
	-- add token to mark the end of this line
	table.insert(tokens,{Token.EOL, ""})
	return tokens
end

function get_lexer(file, parse_tokens)
	-- use the default line tokenizer if one is not provided
	if parse_tokens == nil then parse_tokens = default_parse_tokens end
	-- next/current line code
	local line_num = 0
	local line = nil
	local next_line = io.lines(file)
	-- parse line tokens code
	local get_next_token = nil
	local next_tokens = function ()
		local f, tokens, idx
		repeat
			line_num = line_num + 1
			line = next_line()
			if line == nil then return nil end
			tokens = parse_tokens(line)
		until tokens ~= nil
		-- create get_next_toekn function from table iterator
		f, tokens, idx = ipairs(tokens)
		get_next_token = function()
			idx, token = f(tokens, idx)
			return token
		end
		return tokens
	end

	-- get first group of tokens
	if next_tokens() == nil then
		-- error reading file or empty file
		return nil
	end
	-- build lexer table.
	local lexer = {
	get_token = function ()
		local token
		repeat
			token = get_next_token()
			if token == nil then
				-- get next group of tokens
				if next_tokens() == nil then
					-- end of file.
					return nil
				end
			end
		until token ~= nil
		return token
	end,
	get_line_number = function() return line_num end,
	get_line = function() return line end
	}
	return lexer
end

function print_tokens(file)
	local lexer = get_lexer(file)
	local num = -1
	while true do
		local tok = lexer.get_token()
		if tok == nil then
			break
		end
		if num ~= lexer.get_line_number() then
			num = lexer.get_line_number()
			io.write("\n")
			io.write(string.format("%d: ",num))
		end
		io.write(string.format("%s ",tok[2]))
	end
	io.write("\n")
end

