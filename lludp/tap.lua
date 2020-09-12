
local win_instances = 0

local function create_window_tap(name, create)
	win_instances = win_instances + 1

	local td, tap_filter, tap_type = create()

	-- tap's output window.
	local win = TextWindow.new(name .. " " .. win_instances)

	-- this tap will be local to the menu_function that called it
	local tap = Listener.new(tap_type, tap_filter)

	-- callback to remove the tap when the text window closes
	local function remove_tap()
		if tap and tap.remove then
			tap:remove()
		end
	end

	-- make sure the tap doesn't hang around after the window was closed
	win:set_atclose(remove_tap)

	-- this function will be called for every packet
	function tap.packet(pinfo,tvb, tree, tapdata)
		return td:packet(pinfo, tvb, tree, tapdata)
	end

	-- this function will be called once every few seconds to redraw the window
	function tap.draw()
		local text = td:draw()
		win:set(text)
	end

		-- this function will be called at the end of the capture run.
	function tap.reset()
		return td:reset()
	end
end

local function create_tshark_tap(name, create)

	local td, tap_filter, tap_type = create()

	-- this tap will be local to the menu_function that called it
	local tap = Listener.new(tap_type, tap_filter)

	-- this function will be called for every packet
	function tap.packet(pinfo,tvb,tapdata)
		return td:packet(pinfo, tvb, tapdata)
	end

	-- this function will be called once every few seconds to redraw the window
	function tap.draw()
		local text = td:draw()
		debug(name .. " results:\n" .. text)
	end

		-- this function will be called at the end of the capture run.
	function tap.reset()
		return td:reset()
	end
end

local function register(name, create)
	if gui_enabled() then
		-- menu callback.
		local create_tap = function()
			create_window_tap(name, create)
		end
		-- register menu item if running from wireshark
		register_menu(name, create_tap, MENU_TOOLS_UNSORTED)
	else
		-- we are running from tshark, create a non-gui tap now.
		create_tshark_tap(name, create)
	end
end

return {
	register = register,
}
