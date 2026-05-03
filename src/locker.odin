package locker

import "core:fmt"
import "core:os"
import "core:strings"
import "core:c"
import "core:c/libc"
import "core:time"
import "core:thread"
import x "vendor:x11/xlib"

// PAM bindings
foreign import pam "system:pam"

pam_handle_t :: distinct rawptr
pam_message :: struct {
	msg_style: c.int,
	msg: cstring,
}
pam_response :: struct {
	resp: cstring,
	resp_retcode: c.int,
}
pam_conv :: struct {
	conv: proc "c" (num_msg: c.int, msg: ^[^]pam_message, resp: ^^pam_response, appdata_ptr: rawptr) -> c.int,
	appdata_ptr: rawptr,
}

PAM_PROMPT_ECHO_OFF :: 1
PAM_PROMPT_ECHO_ON :: 2
PAM_ERROR_MSG :: 3
PAM_TEXT_INFO :: 4
PAM_SUCCESS :: 0

@(default_calling_convention="c")
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

	// PAM will free these with free(), so we must use malloc
	responses := ([^]pam_response)(libc.calloc(c.size_t(num_msg), size_of(pam_response)))
	if responses == nil {
		return 1
	}

	messages := msg^
	for i in 0..<num_msg {
		if messages[i].msg_style == PAM_PROMPT_ECHO_OFF || messages[i].msg_style == PAM_PROMPT_ECHO_ON {
			// PAM will free resp with free(), so we must use malloc
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

	conv := pam_conv{
		conv = pam_conversation_func,
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

// Grab keyboard with retry logic
grab_keyboard :: proc(display: ^x.Display, window: x.Window, max_attempts: int = 50) -> bool {
	for _ in 0..<max_attempts {
		result := x.GrabKeyboard(display, window, true, x.GrabMode.GrabModeAsync, x.GrabMode.GrabModeAsync, x.CurrentTime)
		if result == 0 { // GrabSuccess
			return true
		}
		time.sleep(10 * time.Millisecond)
	}
	return false
}

// Grab pointer with retry logic
grab_pointer :: proc(display: ^x.Display, window: x.Window, max_attempts: int = 50) -> bool {
	for _ in 0..<max_attempts {
		result := x.GrabPointer(display, window, true, x.EventMask{}, x.GrabMode.GrabModeAsync, x.GrabMode.GrabModeAsync, window, 0, x.CurrentTime)
		if result == 0 { // GrabSuccess
			return true
		}
		time.sleep(10 * time.Millisecond)
	}
	return false
}

// PAM auth result for thread communication
PamResult :: struct {
	done: bool,
	success: bool,
}

// Global storage for thread-safe password passing
global_password_for_thread: [256]u8
global_password_len: int
global_pam_result: ^PamResult

// Wrapper for threaded PAM authentication
pam_auth_thread :: proc(t: ^thread.Thread) {
	password := string(global_password_for_thread[:global_password_len])
	global_pam_result.success = verify_password(password)
	global_pam_result.done = true
}

// Verify password with timeout
verify_password_with_timeout :: proc(password: string, timeout_seconds: int = 10) -> bool {
	if len(password) > 255 {
		return false
	}

	// Copy password to global buffer for thread
	for i in 0..<len(password) {
		global_password_for_thread[i] = password[i]
	}
	global_password_len = len(password)

	result := PamResult{done = false, success = false}
	global_pam_result = &result

	t := thread.create(pam_auth_thread)
	if t == nil {
		// Fallback to direct call if thread creation fails
		return verify_password(password)
	}
	thread.start(t)

	// Wait with timeout
	deadline := time.now()._nsec + i64(timeout_seconds) * 1_000_000_000
	for !result.done {
		if time.now()._nsec > deadline {
			// Timeout - thread is still running but we give up waiting
			// Note: thread will continue in background, but we won't deadlock
			thread.destroy(t)
			return false
		}
		time.sleep(50 * time.Millisecond)
	}

	thread.join(t)
	thread.destroy(t)
	return result.success
}

main :: proc() {
	display := x.OpenDisplay(nil)
	if display == nil {
		fmt.eprintln("Failed to open X display")
		os.exit(1)
	}
	defer x.CloseDisplay(display)

	screen := x.DefaultScreen(display)
	root := x.RootWindow(display, screen)

	screen_width := x.DisplayWidth(display, screen)
	screen_height := x.DisplayHeight(display, screen)

	black := x.BlackPixel(display, screen)
	white := x.WhitePixel(display, screen)

	// Set window attributes
	attrs: x.XSetWindowAttributes
	attrs.override_redirect = true
	attrs.background_pixel = black
	attrs.event_mask = x.EventMask{.KeyPress, .Exposure}

	window := x.CreateWindow(
		display,
		root,
		0, 0,
		u32(screen_width), u32(screen_height),
		0,
		x.CopyFromParent,
		x.WindowClass.InputOutput,
		nil,
		x.WindowAttributeMask{.CWOverrideRedirect, .CWBackPixel, .CWEventMask},
		&attrs,
	)

	x.StoreName(display, window, "Screen Locker")

	// Make window fullscreen
	x.MapWindow(display, window)
	x.RaiseWindow(display, window)

	// Grab keyboard and pointer with retry logic
	if !grab_keyboard(display, window) {
		fmt.eprintln("Failed to grab keyboard after retries")
		x.DestroyWindow(display, window)
		os.exit(1)
	}
	if !grab_pointer(display, window) {
		fmt.eprintln("Failed to grab pointer after retries")
		x.UngrabKeyboard(display, x.CurrentTime)
		x.DestroyWindow(display, window)
		os.exit(1)
	}

	gc := x.CreateGC(display, window, x.GCAttributeMask{}, nil)
	x.SetForeground(display, gc, white)

	password_buffer: [dynamic]u8
	defer delete(password_buffer)

	running := true
	needs_redraw := true  // Initial draw

	for running {
		// Non-blocking event loop with XPending
		for x.Pending(display) > 0 {
			event: x.XEvent
			x.NextEvent(display, &event)

			#partial switch event.type {
			case x.EventType.Expose:
				needs_redraw = true

			case x.EventType.KeyPress:
				key_event := event.xkey
				buf: [32]u8
				keysym: x.KeySym
				count := x.LookupString(&key_event, raw_data(&buf), i32(len(buf)), &keysym, nil)

				if keysym == .XK_Return {
					password := string(password_buffer[:])
					if len(password) == 0 {
						clear(&password_buffer)
					} else if verify_password_with_timeout(password) {
						running = false
					} else {
						clear(&password_buffer)
					}
					needs_redraw = true
				} else if keysym == .XK_BackSpace {
					if len(password_buffer) > 0 {
						pop(&password_buffer)
						needs_redraw = true
					}
				} else if count > 0 && buf[0] >= 0x20 && buf[0] <= 0x7E {
					append(&password_buffer, buf[0])
					needs_redraw = true
				}
			}
		}

		// Draw if needed
		if needs_redraw {
			x.ClearWindow(display, window)
			prompt := "Leave Me Alone. I'm Sleeping "
			x.DrawString(display, window, gc, screen_width / 2 - 100, screen_height / 2, raw_data(prompt), i32(len(prompt)))

			dots := strings.repeat("*", len(password_buffer))
			defer delete(dots)
			x.DrawString(display, window, gc, screen_width / 2 - 50, screen_height / 2 + 30, raw_data(dots), i32(len(dots)))

			x.Flush(display)
			needs_redraw = false
		}

		// Small sleep to avoid busy-waiting
		time.sleep(10 * time.Millisecond)
	}

	x.UngrabKeyboard(display, x.CurrentTime)
	x.UngrabPointer(display, x.CurrentTime)
	x.FreeGC(display, gc)
	x.DestroyWindow(display, window)
}
