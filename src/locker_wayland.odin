package locker_wayland

import "core:fmt"
import "core:os"
import "core:strings"
import "core:c"
import "core:c/libc"
import "core:time"
import "core:thread"
import "core:mem"
import "core:sys/posix"

// =============================================================================
// PAM bindings (reused from X11 locker)
// =============================================================================

foreign import pam "system:pam"

pam_handle_t :: distinct rawptr
pam_message :: struct {
	msg_style: c.int,
	msg:       cstring,
}
pam_response :: struct {
	resp:         cstring,
	resp_retcode: c.int,
}
pam_conv :: struct {
	conv:         proc "c" (num_msg: c.int, msg: ^[^]pam_message, resp: ^^pam_response, appdata_ptr: rawptr) -> c.int,
	appdata_ptr:  rawptr,
}

PAM_PROMPT_ECHO_OFF :: 1
PAM_PROMPT_ECHO_ON :: 2
PAM_ERROR_MSG :: 3
PAM_TEXT_INFO :: 4
PAM_SUCCESS :: 0

@(default_calling_convention = "c")
foreign pam {
	pam_start :: proc(service_name: cstring, user: cstring, pam_conversation: ^pam_conv, pamh: ^pam_handle_t) -> c.int ---
	pam_authenticate :: proc(pamh: pam_handle_t, flags: c.int) -> c.int ---
	pam_end :: proc(pamh: pam_handle_t, status: c.int) -> c.int ---
}

// Global password storage for PAM callback
global_password: cstring

pam_conversation_func :: proc "c" (num_msg: c.int, msg: ^[^]pam_message, resp: ^^pam_response, appdata_ptr: rawptr) -> c.int {
	if num_msg <= 0 {
		return 1
	}

	responses := ([^]pam_response)(libc.calloc(c.size_t(num_msg), size_of(pam_response)))
	if responses == nil {
		return 1
	}

	messages := msg^
	for i in 0 ..< num_msg {
		if messages[i].msg_style == PAM_PROMPT_ECHO_OFF || messages[i].msg_style == PAM_PROMPT_ECHO_ON {
			pwd_len := libc.strlen(global_password)
			resp_copy := ([^]c.char)(libc.malloc(pwd_len + 1))
			if resp_copy == nil {
				libc.free(responses)
				return 1
			}
			libc.strcpy(resp_copy, global_password)
			responses[i].resp = cstring(resp_copy)
			responses[i].resp_retcode = 0
		}
	}

	resp^ = responses
	return PAM_SUCCESS
}

verify_password :: proc(password: string) -> bool {
	username := os.get_env("USER")
	if username == "" {
		username = os.get_env("LOGNAME")
	}
	if username == "" {
		return false
	}

	password_cstr := strings.clone_to_cstring(password)
	global_password = password_cstr
	defer delete(password_cstr)
	defer global_password = nil

	username_cstr := strings.clone_to_cstring(username)
	defer delete(username_cstr)

	conv := pam_conv {
		conv        = pam_conversation_func,
		appdata_ptr = nil,
	}

	pamh: pam_handle_t
	ret := pam_start("login", username_cstr, &conv, &pamh)
	if ret != PAM_SUCCESS {
		return false
	}
	defer pam_end(pamh, ret)

	ret = pam_authenticate(pamh, 0)
	return ret == PAM_SUCCESS
}

// PAM auth with timeout
PamResult :: struct {
	done:    bool,
	success: bool,
}

global_password_for_thread: [256]u8
global_password_len: int
global_pam_result: ^PamResult

pam_auth_thread :: proc(t: ^thread.Thread) {
	password := string(global_password_for_thread[:global_password_len])
	global_pam_result.success = verify_password(password)
	global_pam_result.done = true
}

verify_password_with_timeout :: proc(password: string, timeout_seconds: int = 10) -> bool {
	if len(password) > 255 {
		return false
	}

	for i in 0 ..< len(password) {
		global_password_for_thread[i] = password[i]
	}
	global_password_len = len(password)

	result := PamResult {
		done    = false,
		success = false,
	}
	global_pam_result = &result

	t := thread.create(pam_auth_thread)
	if t == nil {
		return verify_password(password)
	}
	thread.start(t)

	deadline := time.now()._nsec + i64(timeout_seconds) * 1_000_000_000
	for !result.done {
		if time.now()._nsec > deadline {
			thread.destroy(t)
			return false
		}
		time.sleep(50 * time.Millisecond)
	}

	thread.join(t)
	thread.destroy(t)
	return result.success
}

// =============================================================================
// Wayland bindings
// =============================================================================

foreign import wl "system:wayland-client"

// Opaque Wayland types
wl_display :: struct {}
wl_registry :: struct {}
wl_compositor :: struct {}
wl_surface :: struct {}
wl_shm :: struct {}
wl_shm_pool :: struct {}
wl_buffer :: struct {}
wl_seat :: struct {}
wl_keyboard :: struct {}
wl_output :: struct {}
wl_callback :: struct {}
wl_proxy :: struct {}

// Interface struct
wl_interface :: struct {
	name:         cstring,
	version:      c.int,
	method_count: c.int,
	methods:      rawptr,
	event_count:  c.int,
	events:       rawptr,
}

Listener_Func :: proc "c" ()

// Listener types
wl_registry_listener :: struct {
	global:        proc "c" (data: rawptr, registry: ^wl_registry, name: u32, interface: cstring, version: u32),
	global_remove: proc "c" (data: rawptr, registry: ^wl_registry, name: u32),
}

wl_seat_listener :: struct {
	capabilities: proc "c" (data: rawptr, seat: ^wl_seat, capabilities: u32),
	name:         proc "c" (data: rawptr, seat: ^wl_seat, name: cstring),
}

wl_keyboard_listener :: struct {
	keymap:      proc "c" (data: rawptr, keyboard: ^wl_keyboard, format: u32, fd: c.int, size: u32),
	enter:       proc "c" (data: rawptr, keyboard: ^wl_keyboard, serial: u32, surface: ^wl_surface, keys: ^wl_array),
	leave:       proc "c" (data: rawptr, keyboard: ^wl_keyboard, serial: u32, surface: ^wl_surface),
	key:         proc "c" (data: rawptr, keyboard: ^wl_keyboard, serial: u32, time: u32, key: u32, state: u32),
	modifiers:   proc "c" (data: rawptr, keyboard: ^wl_keyboard, serial: u32, mods_depressed: u32, mods_latched: u32, mods_locked: u32, group: u32),
	repeat_info: proc "c" (data: rawptr, keyboard: ^wl_keyboard, rate: i32, delay: i32),
}

wl_output_listener :: struct {
	geometry:    proc "c" (data: rawptr, output: ^wl_output, x: i32, y: i32, physical_width: i32, physical_height: i32, subpixel: i32, make: cstring, model: cstring, transform: i32),
	mode:        proc "c" (data: rawptr, output: ^wl_output, flags: u32, width: i32, height: i32, refresh: i32),
	done:        proc "c" (data: rawptr, output: ^wl_output),
	scale:       proc "c" (data: rawptr, output: ^wl_output, factor: i32),
	name:        proc "c" (data: rawptr, output: ^wl_output, name: cstring),
	description: proc "c" (data: rawptr, output: ^wl_output, description: cstring),
}

wl_buffer_listener :: struct {
	release: proc "c" (data: rawptr, buffer: ^wl_buffer),
}

wl_array :: struct {
	size:  c.size_t,
	alloc: c.size_t,
	data:  rawptr,
}

// Wayland constants
WL_SEAT_CAPABILITY_KEYBOARD :: 2
WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 :: 1
WL_SHM_FORMAT_ARGB8888 :: 0
WL_KEYBOARD_KEY_STATE_PRESSED :: 1
WL_MARSHAL_FLAG_DESTROY :: 1

// Protocol opcodes
WL_DISPLAY_GET_REGISTRY :: 1
WL_REGISTRY_BIND :: 0
WL_COMPOSITOR_CREATE_SURFACE :: 0
WL_SURFACE_DESTROY :: 0
WL_SURFACE_ATTACH :: 1
WL_SURFACE_COMMIT :: 6
WL_SURFACE_DAMAGE_BUFFER :: 9
WL_SHM_CREATE_POOL :: 0
WL_SHM_POOL_CREATE_BUFFER :: 0
WL_SHM_POOL_DESTROY :: 1
WL_BUFFER_DESTROY :: 0
WL_SEAT_GET_KEYBOARD :: 1
WL_KEYBOARD_RELEASE :: 0

// Core library functions
@(default_calling_convention = "c")
foreign wl {
	wl_display_connect :: proc(name: cstring) -> ^wl_display ---
	wl_display_disconnect :: proc(display: ^wl_display) ---
	wl_display_dispatch :: proc(display: ^wl_display) -> c.int ---
	wl_display_dispatch_pending :: proc(display: ^wl_display) -> c.int ---
	wl_display_roundtrip :: proc(display: ^wl_display) -> c.int ---
	wl_display_flush :: proc(display: ^wl_display) -> c.int ---
	wl_display_get_fd :: proc(display: ^wl_display) -> c.int ---

	wl_proxy_marshal_flags :: proc(proxy: ^wl_proxy, opcode: u32, interface: ^wl_interface, version: u32, flags: u32, #c_vararg args: ..any) -> ^wl_proxy ---
	wl_proxy_add_listener :: proc(proxy: ^wl_proxy, implementation: ^Listener_Func, data: rawptr) -> c.int ---
	wl_proxy_get_version :: proc(proxy: ^wl_proxy) -> u32 ---
	wl_proxy_destroy :: proc(proxy: ^wl_proxy) ---

	// Interface externs
	wl_registry_interface: wl_interface
	wl_compositor_interface: wl_interface
	wl_shm_interface: wl_interface
	wl_shm_pool_interface: wl_interface
	wl_buffer_interface: wl_interface
	wl_seat_interface: wl_interface
	wl_keyboard_interface: wl_interface
	wl_output_interface: wl_interface
	wl_surface_interface: wl_interface
}

// Wrapper functions for Wayland protocol calls
wl_display_get_registry :: proc(display: ^wl_display) -> ^wl_registry {
	return (^wl_registry)(wl_proxy_marshal_flags(
		(^wl_proxy)(display),
		WL_DISPLAY_GET_REGISTRY,
		&wl_registry_interface,
		1,
		0,
		nil,
	))
}

wl_registry_add_listener :: proc(registry: ^wl_registry, listener: ^wl_registry_listener, data: rawptr) -> c.int {
	return wl_proxy_add_listener((^wl_proxy)(registry), (^Listener_Func)(listener), data)
}

wl_registry_bind :: proc(registry: ^wl_registry, name: u32, interface: ^wl_interface, version: u32) -> rawptr {
	return wl_proxy_marshal_flags(
		(^wl_proxy)(registry),
		WL_REGISTRY_BIND,
		interface,
		version,
		0,
		name,
		interface.name,
		version,
		nil,
	)
}

wl_compositor_create_surface :: proc(compositor: ^wl_compositor) -> ^wl_surface {
	return (^wl_surface)(wl_proxy_marshal_flags(
		(^wl_proxy)(compositor),
		WL_COMPOSITOR_CREATE_SURFACE,
		&wl_surface_interface,
		wl_proxy_get_version((^wl_proxy)(compositor)),
		0,
		nil,
	))
}

wl_surface_attach :: proc(surface: ^wl_surface, buffer: ^wl_buffer, x: i32, y: i32) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(surface),
		WL_SURFACE_ATTACH,
		nil,
		wl_proxy_get_version((^wl_proxy)(surface)),
		0,
		buffer,
		x,
		y,
	)
}

wl_surface_commit :: proc(surface: ^wl_surface) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(surface),
		WL_SURFACE_COMMIT,
		nil,
		wl_proxy_get_version((^wl_proxy)(surface)),
		0,
	)
}

wl_surface_damage_buffer :: proc(surface: ^wl_surface, x: i32, y: i32, width: i32, height: i32) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(surface),
		WL_SURFACE_DAMAGE_BUFFER,
		nil,
		wl_proxy_get_version((^wl_proxy)(surface)),
		0,
		x,
		y,
		width,
		height,
	)
}

wl_surface_destroy :: proc(surface: ^wl_surface) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(surface),
		WL_SURFACE_DESTROY,
		nil,
		wl_proxy_get_version((^wl_proxy)(surface)),
		WL_MARSHAL_FLAG_DESTROY,
	)
}

wl_shm_create_pool :: proc(shm: ^wl_shm, fd: c.int, size: i32) -> ^wl_shm_pool {
	return (^wl_shm_pool)(wl_proxy_marshal_flags(
		(^wl_proxy)(shm),
		WL_SHM_CREATE_POOL,
		&wl_shm_pool_interface,
		wl_proxy_get_version((^wl_proxy)(shm)),
		0,
		nil,
		fd,
		size,
	))
}

wl_shm_pool_create_buffer :: proc(pool: ^wl_shm_pool, offset: i32, width: i32, height: i32, stride: i32, format: u32) -> ^wl_buffer {
	return (^wl_buffer)(wl_proxy_marshal_flags(
		(^wl_proxy)(pool),
		WL_SHM_POOL_CREATE_BUFFER,
		&wl_buffer_interface,
		wl_proxy_get_version((^wl_proxy)(pool)),
		0,
		nil,
		offset,
		width,
		height,
		stride,
		format,
	))
}

wl_shm_pool_destroy :: proc(pool: ^wl_shm_pool) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(pool),
		WL_SHM_POOL_DESTROY,
		nil,
		wl_proxy_get_version((^wl_proxy)(pool)),
		WL_MARSHAL_FLAG_DESTROY,
	)
}

wl_buffer_destroy :: proc(buffer: ^wl_buffer) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(buffer),
		WL_BUFFER_DESTROY,
		nil,
		wl_proxy_get_version((^wl_proxy)(buffer)),
		WL_MARSHAL_FLAG_DESTROY,
	)
}

wl_seat_add_listener :: proc(seat: ^wl_seat, listener: ^wl_seat_listener, data: rawptr) -> c.int {
	return wl_proxy_add_listener((^wl_proxy)(seat), (^Listener_Func)(listener), data)
}

wl_seat_get_keyboard :: proc(seat: ^wl_seat) -> ^wl_keyboard {
	return (^wl_keyboard)(wl_proxy_marshal_flags(
		(^wl_proxy)(seat),
		WL_SEAT_GET_KEYBOARD,
		&wl_keyboard_interface,
		wl_proxy_get_version((^wl_proxy)(seat)),
		0,
		nil,
	))
}

wl_keyboard_add_listener :: proc(keyboard: ^wl_keyboard, listener: ^wl_keyboard_listener, data: rawptr) -> c.int {
	return wl_proxy_add_listener((^wl_proxy)(keyboard), (^Listener_Func)(listener), data)
}

wl_keyboard_destroy :: proc(keyboard: ^wl_keyboard) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(keyboard),
		WL_KEYBOARD_RELEASE,
		nil,
		wl_proxy_get_version((^wl_proxy)(keyboard)),
		WL_MARSHAL_FLAG_DESTROY,
	)
}

wl_output_add_listener :: proc(output: ^wl_output, listener: ^wl_output_listener, data: rawptr) -> c.int {
	return wl_proxy_add_listener((^wl_proxy)(output), (^Listener_Func)(listener), data)
}

// =============================================================================
// ext-session-lock-v1 protocol bindings
// =============================================================================

ext_session_lock_manager_v1 :: struct {}
ext_session_lock_v1 :: struct {}
ext_session_lock_surface_v1 :: struct {}

ext_session_lock_v1_listener :: struct {
	locked:   proc "c" (data: rawptr, lock: ^ext_session_lock_v1),
	finished: proc "c" (data: rawptr, lock: ^ext_session_lock_v1),
}

ext_session_lock_surface_v1_listener :: struct {
	configure: proc "c" (data: rawptr, lock_surface: ^ext_session_lock_surface_v1, serial: u32, width: u32, height: u32),
}

// Protocol opcodes
EXT_SESSION_LOCK_MANAGER_V1_DESTROY :: 0
EXT_SESSION_LOCK_MANAGER_V1_LOCK :: 1

EXT_SESSION_LOCK_V1_DESTROY :: 0
EXT_SESSION_LOCK_V1_GET_LOCK_SURFACE :: 1
EXT_SESSION_LOCK_V1_UNLOCK_AND_DESTROY :: 2

EXT_SESSION_LOCK_SURFACE_V1_DESTROY :: 0
EXT_SESSION_LOCK_SURFACE_V1_ACK_CONFIGURE :: 1

// Protocol interface definitions (manually defined since no generated code)
ext_session_lock_manager_v1_interface := wl_interface {
	name         = "ext_session_lock_manager_v1",
	version      = 1,
	method_count = 2,
	methods      = nil,
	event_count  = 0,
	events       = nil,
}

ext_session_lock_v1_interface := wl_interface {
	name         = "ext_session_lock_v1",
	version      = 1,
	method_count = 3,
	methods      = nil,
	event_count  = 2,
	events       = nil,
}

ext_session_lock_surface_v1_interface := wl_interface {
	name         = "ext_session_lock_surface_v1",
	version      = 1,
	method_count = 2,
	methods      = nil,
	event_count  = 1,
	events       = nil,
}

// Session lock helper functions
ext_session_lock_manager_v1_lock :: proc(manager: ^ext_session_lock_manager_v1) -> ^ext_session_lock_v1 {
	return (^ext_session_lock_v1)(wl_proxy_marshal_flags(
		(^wl_proxy)(manager),
		EXT_SESSION_LOCK_MANAGER_V1_LOCK,
		&ext_session_lock_v1_interface,
		1, // version
		0, // flags
		nil, // new_id placeholder
	))
}

ext_session_lock_v1_get_lock_surface :: proc(lock: ^ext_session_lock_v1, surface: ^wl_surface, output: ^wl_output) -> ^ext_session_lock_surface_v1 {
	return (^ext_session_lock_surface_v1)(wl_proxy_marshal_flags(
		(^wl_proxy)(lock),
		EXT_SESSION_LOCK_V1_GET_LOCK_SURFACE,
		&ext_session_lock_surface_v1_interface,
		1, // version
		0, // flags
		nil, // new_id placeholder
		surface,
		output,
	))
}

ext_session_lock_v1_unlock_and_destroy :: proc(lock: ^ext_session_lock_v1) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(lock),
		EXT_SESSION_LOCK_V1_UNLOCK_AND_DESTROY,
		nil,
		1, // version
		1, // WL_MARSHAL_FLAG_DESTROY
	)
}

ext_session_lock_v1_add_listener :: proc(lock: ^ext_session_lock_v1, listener: ^ext_session_lock_v1_listener, data: rawptr) -> c.int {
	return wl_proxy_add_listener((^wl_proxy)(lock), (^Listener_Func)(listener), data)
}

ext_session_lock_surface_v1_add_listener :: proc(lock_surface: ^ext_session_lock_surface_v1, listener: ^ext_session_lock_surface_v1_listener, data: rawptr) -> c.int {
	return wl_proxy_add_listener((^wl_proxy)(lock_surface), (^Listener_Func)(listener), data)
}

ext_session_lock_surface_v1_ack_configure :: proc(lock_surface: ^ext_session_lock_surface_v1, serial: u32) {
	wl_proxy_marshal_flags(
		(^wl_proxy)(lock_surface),
		EXT_SESSION_LOCK_SURFACE_V1_ACK_CONFIGURE,
		nil,
		1, // version
		0, // flags
		serial,
	)
}

// =============================================================================
// xkbcommon bindings
// =============================================================================

foreign import xkb "system:xkbcommon"

xkb_context :: struct {}
xkb_keymap :: struct {}
xkb_state :: struct {}
xkb_keysym_t :: u32

XKB_CONTEXT_NO_FLAGS :: 0
XKB_KEYMAP_COMPILE_NO_FLAGS :: 0
XKB_KEYMAP_FORMAT_TEXT_V1 :: 1

// Common keysyms
XKB_KEY_Return :: 0xff0d
XKB_KEY_BackSpace :: 0xff08
XKB_KEY_Escape :: 0xff1b

@(default_calling_convention = "c")
foreign xkb {
	xkb_context_new :: proc(flags: c.int) -> ^xkb_context ---
	xkb_context_unref :: proc(ctx: ^xkb_context) ---

	xkb_keymap_new_from_string :: proc(ctx: ^xkb_context, str: cstring, format: c.int, flags: c.int) -> ^xkb_keymap ---
	xkb_keymap_unref :: proc(keymap: ^xkb_keymap) ---

	xkb_state_new :: proc(keymap: ^xkb_keymap) -> ^xkb_state ---
	xkb_state_unref :: proc(state: ^xkb_state) ---
	xkb_state_key_get_one_sym :: proc(state: ^xkb_state, key: u32) -> xkb_keysym_t ---
	xkb_state_key_get_utf8 :: proc(state: ^xkb_state, key: u32, buffer: [^]u8, size: c.size_t) -> c.int ---
	xkb_state_update_mask :: proc(state: ^xkb_state, depressed_mods: u32, latched_mods: u32, locked_mods: u32, depressed_layout: u32, latched_layout: u32, locked_layout: u32) -> c.int ---
}

// =============================================================================
// Linux syscalls
// =============================================================================

foreign import libc_sys "system:c"

@(default_calling_convention = "c")
foreign libc_sys {
	memfd_create :: proc(name: cstring, flags: c.uint) -> c.int ---
	ftruncate :: proc(fd: c.int, length: c.long) -> c.int ---
	mmap :: proc(addr: rawptr, length: c.size_t, prot: c.int, flags: c.int, fd: c.int, offset: c.long) -> rawptr ---
	munmap :: proc(addr: rawptr, length: c.size_t) -> c.int ---
	close :: proc(fd: c.int) -> c.int ---
	poll :: proc(fds: ^pollfd, nfds: c.ulong, timeout: c.int) -> c.int ---
}

pollfd :: struct {
	fd:      c.int,
	events:  c.short,
	revents: c.short,
}

PROT_READ :: 0x1
PROT_WRITE :: 0x2
MAP_SHARED :: 0x01
MAP_FAILED :: rawptr(~uintptr(0))
POLLIN :: 0x001

// =============================================================================
// Color definitions (ARGB8888)
// =============================================================================

COLOR_BLACK :: 0xFF000000     // Idle
COLOR_DARK_GRAY :: 0xFF333333 // Typing
COLOR_BLUE :: 0xFF0066CC      // Verifying
COLOR_RED :: 0xFFCC0000       // Auth failed

// =============================================================================
// Application state
// =============================================================================

LockState :: enum {
	Idle,       // Black - waiting for input
	Typing,     // Dark gray - has characters
	Verifying,  // Blue - checking password
	Failed,     // Red flash
}

OutputInfo :: struct {
	output:           ^wl_output,
	name:             u32,
	width:            i32,
	height:           i32,
	scale:            i32,
	surface:          ^wl_surface,
	lock_surface:     ^ext_session_lock_surface_v1,
	buffer:           ^wl_buffer,
	shm_pool:         ^wl_shm_pool,
	shm_data:         [^]u32,
	shm_fd:           c.int,
	shm_size:         c.size_t,
	configured:       bool,
	pending_width:    u32,
	pending_height:   u32,
	pending_serial:   u32,
	needs_configure:  bool,
}

AppState :: struct {
	display:            ^wl_display,
	registry:           ^wl_registry,
	compositor:         ^wl_compositor,
	shm:                ^wl_shm,
	seat:               ^wl_seat,
	keyboard:           ^wl_keyboard,
	lock_manager:       ^ext_session_lock_manager_v1,
	lock:               ^ext_session_lock_v1,

	outputs:            [dynamic]^OutputInfo,

	xkb_ctx:            ^xkb_context,
	xkb_keymap:         ^xkb_keymap,
	xkb_state:          ^xkb_state,

	password_buffer:    [dynamic]u8,
	lock_state:         LockState,
	locked:             bool,
	running:            bool,
	needs_redraw:       bool,

	failed_flash_start: i64,
}

state: AppState

// =============================================================================
// Wayland listeners
// =============================================================================

registry_listener := wl_registry_listener {
	global        = registry_global,
	global_remove = registry_global_remove,
}

registry_global :: proc "c" (data: rawptr, registry: ^wl_registry, name: u32, interface: cstring, version: u32) {
	context = {}
	interface_str := string(interface)

	if interface_str == "wl_compositor" {
		state.compositor = (^wl_compositor)(wl_registry_bind(registry, name, &wl_compositor_interface, 4))
	} else if interface_str == "wl_shm" {
		state.shm = (^wl_shm)(wl_registry_bind(registry, name, &wl_shm_interface, 1))
	} else if interface_str == "wl_seat" {
		state.seat = (^wl_seat)(wl_registry_bind(registry, name, &wl_seat_interface, 5))
		wl_seat_add_listener(state.seat, &seat_listener, nil)
	} else if interface_str == "wl_output" {
		output := (^wl_output)(wl_registry_bind(registry, name, &wl_output_interface, 4))
		output_info := new(OutputInfo)
		output_info.output = output
		output_info.name = name
		output_info.width = 1920 // Default, will be updated
		output_info.height = 1080
		output_info.scale = 1
		output_info.shm_fd = -1
		append(&state.outputs, output_info)
		wl_output_add_listener(output, &output_listener, output_info)
	} else if interface_str == "ext_session_lock_manager_v1" {
		state.lock_manager = (^ext_session_lock_manager_v1)(wl_registry_bind(registry, name, &ext_session_lock_manager_v1_interface, 1))
	}
}

registry_global_remove :: proc "c" (data: rawptr, registry: ^wl_registry, name: u32) {
	// Handle output removal if needed
}

seat_listener := wl_seat_listener {
	capabilities = seat_capabilities,
	name         = seat_name,
}

seat_capabilities :: proc "c" (data: rawptr, seat: ^wl_seat, capabilities: u32) {
	context = {}
	if (capabilities & WL_SEAT_CAPABILITY_KEYBOARD) != 0 && state.keyboard == nil {
		state.keyboard = wl_seat_get_keyboard(seat)
		wl_keyboard_add_listener(state.keyboard, &keyboard_listener, nil)
	}
}

seat_name :: proc "c" (data: rawptr, seat: ^wl_seat, name: cstring) {
}

keyboard_listener := wl_keyboard_listener {
	keymap      = keyboard_keymap,
	enter       = keyboard_enter,
	leave       = keyboard_leave,
	key         = keyboard_key,
	modifiers   = keyboard_modifiers,
	repeat_info = keyboard_repeat_info,
}

keyboard_keymap :: proc "c" (data: rawptr, keyboard: ^wl_keyboard, format: u32, fd: c.int, size: u32) {
	if format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 {
		close(fd)
		return
	}

	map_str := mmap(nil, c.size_t(size), PROT_READ, MAP_SHARED, fd, 0)
	if map_str == MAP_FAILED {
		close(fd)
		return
	}

	if state.xkb_keymap != nil {
		xkb_keymap_unref(state.xkb_keymap)
	}
	if state.xkb_state != nil {
		xkb_state_unref(state.xkb_state)
	}

	state.xkb_keymap = xkb_keymap_new_from_string(state.xkb_ctx, cstring(map_str), XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS)
	munmap(map_str, c.size_t(size))
	close(fd)

	if state.xkb_keymap != nil {
		state.xkb_state = xkb_state_new(state.xkb_keymap)
	}
}

keyboard_enter :: proc "c" (data: rawptr, keyboard: ^wl_keyboard, serial: u32, surface: ^wl_surface, keys: ^wl_array) {
}

keyboard_leave :: proc "c" (data: rawptr, keyboard: ^wl_keyboard, serial: u32, surface: ^wl_surface) {
}

keyboard_key :: proc "c" (data: rawptr, keyboard: ^wl_keyboard, serial: u32, time: u32, key: u32, key_state: u32) {
	context = {}

	if key_state != WL_KEYBOARD_KEY_STATE_PRESSED || state.xkb_state == nil {
		return
	}

	// XKB uses evdev keycodes (key + 8)
	keycode := key + 8
	keysym := xkb_state_key_get_one_sym(state.xkb_state, keycode)

	if keysym == XKB_KEY_Return {
		handle_return()
	} else if keysym == XKB_KEY_BackSpace {
		handle_backspace()
	} else if keysym == XKB_KEY_Escape {
		// Clear password on escape
		clear(&state.password_buffer)
		state.lock_state = .Idle
		state.needs_redraw = true
	} else {
		// Get UTF-8 representation
		buf: [8]u8
		len := xkb_state_key_get_utf8(state.xkb_state, keycode, &buf[0], 8)
		if len > 0 && buf[0] >= 0x20 && buf[0] != 0x7F {
			for i in 0 ..< len {
				append(&state.password_buffer, buf[i])
			}
			state.lock_state = .Typing
			state.needs_redraw = true
		}
	}
}

keyboard_modifiers :: proc "c" (data: rawptr, keyboard: ^wl_keyboard, serial: u32, mods_depressed: u32, mods_latched: u32, mods_locked: u32, group: u32) {
	if state.xkb_state != nil {
		xkb_state_update_mask(state.xkb_state, mods_depressed, mods_latched, mods_locked, 0, 0, group)
	}
}

keyboard_repeat_info :: proc "c" (data: rawptr, keyboard: ^wl_keyboard, rate: i32, delay: i32) {
}

output_listener := wl_output_listener {
	geometry    = output_geometry,
	mode        = output_mode,
	done        = output_done,
	scale       = output_scale,
	name        = output_name,
	description = output_description,
}

output_geometry :: proc "c" (data: rawptr, output: ^wl_output, x: i32, y: i32, physical_width: i32, physical_height: i32, subpixel: i32, make: cstring, model: cstring, transform: i32) {
}

output_mode :: proc "c" (data: rawptr, output: ^wl_output, flags: u32, width: i32, height: i32, refresh: i32) {
	output_info := (^OutputInfo)(data)
	// Use current mode (flags & 1 == WL_OUTPUT_MODE_CURRENT)
	if (flags & 1) != 0 {
		output_info.width = width
		output_info.height = height
	}
}

output_done :: proc "c" (data: rawptr, output: ^wl_output) {
}

output_scale :: proc "c" (data: rawptr, output: ^wl_output, factor: i32) {
	output_info := (^OutputInfo)(data)
	output_info.scale = factor
}

output_name :: proc "c" (data: rawptr, output: ^wl_output, name: cstring) {
}

output_description :: proc "c" (data: rawptr, output: ^wl_output, description: cstring) {
}

lock_listener := ext_session_lock_v1_listener {
	locked   = lock_locked,
	finished = lock_finished,
}

lock_locked :: proc "c" (data: rawptr, lock: ^ext_session_lock_v1) {
	state.locked = true
}

lock_finished :: proc "c" (data: rawptr, lock: ^ext_session_lock_v1) {
	// Lock was rejected or session ended
	state.running = false
}

lock_surface_listener := ext_session_lock_surface_v1_listener {
	configure = lock_surface_configure,
}

lock_surface_configure :: proc "c" (data: rawptr, lock_surface: ^ext_session_lock_surface_v1, serial: u32, width: u32, height: u32) {
	output_info := (^OutputInfo)(data)
	output_info.pending_width = width
	output_info.pending_height = height
	output_info.pending_serial = serial
	output_info.needs_configure = true
}

// =============================================================================
// Buffer management
// =============================================================================

create_buffer :: proc(output_info: ^OutputInfo, width: i32, height: i32) -> bool {
	stride := width * 4
	size := c.size_t(stride * height)

	// Clean up old buffer if exists
	if output_info.buffer != nil {
		wl_buffer_destroy(output_info.buffer)
		output_info.buffer = nil
	}
	if output_info.shm_pool != nil {
		wl_shm_pool_destroy(output_info.shm_pool)
		output_info.shm_pool = nil
	}
	if output_info.shm_data != nil {
		munmap(output_info.shm_data, output_info.shm_size)
		output_info.shm_data = nil
	}
	if output_info.shm_fd >= 0 {
		close(output_info.shm_fd)
		output_info.shm_fd = -1
	}

	fd := memfd_create("locker-buffer", 0)
	if fd < 0 {
		return false
	}

	if ftruncate(fd, c.long(size)) < 0 {
		close(fd)
		return false
	}

	data := mmap(nil, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
	if data == MAP_FAILED {
		close(fd)
		return false
	}

	pool := wl_shm_create_pool(state.shm, fd, i32(size))
	if pool == nil {
		munmap(data, size)
		close(fd)
		return false
	}

	buffer := wl_shm_pool_create_buffer(pool, 0, width, height, stride, WL_SHM_FORMAT_ARGB8888)
	if buffer == nil {
		wl_shm_pool_destroy(pool)
		munmap(data, size)
		close(fd)
		return false
	}

	output_info.shm_fd = fd
	output_info.shm_data = ([^]u32)(data)
	output_info.shm_size = size
	output_info.shm_pool = pool
	output_info.buffer = buffer
	output_info.width = width
	output_info.height = height

	return true
}

fill_color :: proc(output_info: ^OutputInfo, color: u32) {
	if output_info.shm_data == nil {
		return
	}
	pixel_count := output_info.width * output_info.height
	for i in 0 ..< pixel_count {
		output_info.shm_data[i] = color
	}
}

// =============================================================================
// Input handling
// =============================================================================

handle_return :: proc() {
	if len(state.password_buffer) == 0 {
		// Empty password - do nothing, stay in current state
		return
	}

	state.lock_state = .Verifying
	state.needs_redraw = true
	redraw_all()

	password := string(state.password_buffer[:])
	if verify_password_with_timeout(password) {
		// Success - unlock
		ext_session_lock_v1_unlock_and_destroy(state.lock)
		state.running = false
	} else {
		// Failed - flash red
		clear(&state.password_buffer)
		state.lock_state = .Failed
		state.failed_flash_start = time.now()._nsec
		state.needs_redraw = true
	}
}

handle_backspace :: proc() {
	if len(state.password_buffer) > 0 {
		pop(&state.password_buffer)
		if len(state.password_buffer) == 0 {
			state.lock_state = .Idle
		}
		state.needs_redraw = true
	}
}

// =============================================================================
// Rendering
// =============================================================================

get_state_color :: proc() -> u32 {
	#partial switch state.lock_state {
	case .Idle:
		return COLOR_BLACK
	case .Typing:
		return COLOR_DARK_GRAY
	case .Verifying:
		return COLOR_BLUE
	case .Failed:
		return COLOR_RED
	}
	return COLOR_BLACK
}

redraw_all :: proc() {
	color := get_state_color()

	for output_info in state.outputs {
		if output_info.configured && output_info.buffer != nil {
			fill_color(output_info, color)
			wl_surface_attach(output_info.surface, output_info.buffer, 0, 0)
			wl_surface_damage_buffer(output_info.surface, 0, 0, output_info.width, output_info.height)
			wl_surface_commit(output_info.surface)
		}
	}

	wl_display_flush(state.display)
	state.needs_redraw = false
}

// =============================================================================
// Main
// =============================================================================

main :: proc() {
	// Connect to Wayland
	state.display = wl_display_connect(nil)
	if state.display == nil {
		fmt.eprintln("Failed to connect to Wayland display")
		os.exit(1)
	}
	defer wl_display_disconnect(state.display)

	// Initialize xkbcommon
	state.xkb_ctx = xkb_context_new(XKB_CONTEXT_NO_FLAGS)
	if state.xkb_ctx == nil {
		fmt.eprintln("Failed to create xkb context")
		os.exit(1)
	}
	defer xkb_context_unref(state.xkb_ctx)

	// Get registry
	state.registry = wl_display_get_registry(state.display)
	wl_registry_add_listener(state.registry, &registry_listener, nil)
	wl_display_roundtrip(state.display)
	wl_display_roundtrip(state.display)

	// Verify required globals
	if state.compositor == nil {
		fmt.eprintln("Compositor not available")
		os.exit(1)
	}
	if state.shm == nil {
		fmt.eprintln("Shared memory not available")
		os.exit(1)
	}
	if state.lock_manager == nil {
		fmt.eprintln("ext-session-lock-v1 not supported by compositor")
		os.exit(1)
	}
	if len(state.outputs) == 0 {
		fmt.eprintln("No outputs found")
		os.exit(1)
	}

	// Request session lock
	state.lock = ext_session_lock_manager_v1_lock(state.lock_manager)
	if state.lock == nil {
		fmt.eprintln("Failed to create session lock")
		os.exit(1)
	}
	ext_session_lock_v1_add_listener(state.lock, &lock_listener, nil)

	// Create lock surfaces for all outputs
	for output_info in state.outputs {
		output_info.surface = wl_compositor_create_surface(state.compositor)
		if output_info.surface == nil {
			fmt.eprintln("Failed to create surface")
			os.exit(1)
		}

		output_info.lock_surface = ext_session_lock_v1_get_lock_surface(state.lock, output_info.surface, output_info.output)
		if output_info.lock_surface == nil {
			fmt.eprintln("Failed to create lock surface")
			os.exit(1)
		}
		ext_session_lock_surface_v1_add_listener(output_info.lock_surface, &lock_surface_listener, output_info)

		wl_surface_commit(output_info.surface)
	}

	wl_display_flush(state.display)

	// Wait for lock confirmation
	for !state.locked && state.running {
		if wl_display_dispatch(state.display) < 0 {
			fmt.eprintln("Wayland dispatch error")
			os.exit(1)
		}
	}

	// Ensure we're still running (lock wasn't rejected)
	state.running = state.locked
	state.lock_state = .Idle
	state.needs_redraw = true

	// Main event loop
	display_fd := wl_display_get_fd(state.display)

	for state.running {
		// Process any pending configure events
		for output_info in state.outputs {
			if output_info.needs_configure {
				width := i32(output_info.pending_width)
				height := i32(output_info.pending_height)

				if width > 0 && height > 0 {
					if create_buffer(output_info, width, height) {
						ext_session_lock_surface_v1_ack_configure(output_info.lock_surface, output_info.pending_serial)
						output_info.configured = true
						state.needs_redraw = true
					}
				}
				output_info.needs_configure = false
			}
		}

		// Handle failed state timeout (flash red for 200ms)
		if state.lock_state == .Failed {
			elapsed := time.now()._nsec - state.failed_flash_start
			if elapsed > 200_000_000 { // 200ms
				state.lock_state = .Idle
				state.needs_redraw = true
			}
		}

		// Redraw if needed
		if state.needs_redraw {
			redraw_all()
		}

		// Flush and wait for events
		wl_display_flush(state.display)

		fds := pollfd {
			fd     = display_fd,
			events = POLLIN,
		}
		poll(&fds, 1, 16) // ~60fps max for smooth flash animation

		if (fds.revents & POLLIN) != 0 {
			if wl_display_dispatch(state.display) < 0 {
				break
			}
		} else {
			wl_display_dispatch_pending(state.display)
		}
	}

	// Cleanup
	if state.xkb_state != nil {
		xkb_state_unref(state.xkb_state)
	}
	if state.xkb_keymap != nil {
		xkb_keymap_unref(state.xkb_keymap)
	}
	if state.keyboard != nil {
		wl_keyboard_destroy(state.keyboard)
	}

	for output_info in state.outputs {
		if output_info.buffer != nil {
			wl_buffer_destroy(output_info.buffer)
		}
		if output_info.shm_pool != nil {
			wl_shm_pool_destroy(output_info.shm_pool)
		}
		if output_info.shm_data != nil {
			munmap(output_info.shm_data, output_info.shm_size)
		}
		if output_info.shm_fd >= 0 {
			close(output_info.shm_fd)
		}
		if output_info.surface != nil {
			wl_surface_destroy(output_info.surface)
		}
		free(output_info)
	}
	delete(state.outputs)
	delete(state.password_buffer)
}
