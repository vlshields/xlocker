package locker

import "core:fmt"
import "core:os"
import "core:strings"
import "core:c"
import "core:mem"
import "base:runtime"
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
	context = runtime.default_context()

	if num_msg <= 0 {
		return 1
	}

	size := int(num_msg) * size_of(pam_response)
	responses_ptr, err := mem.alloc_bytes(size, align_of(pam_response))
	if err != nil {
		return 1
	}
	mem.zero(raw_data(responses_ptr), size)
	responses := ([^]pam_response)(raw_data(responses_ptr))

	messages := msg^
	for i in 0..<num_msg {
		if messages[i].msg_style == PAM_PROMPT_ECHO_OFF || messages[i].msg_style == PAM_PROMPT_ECHO_ON {
			responses[i].resp = global_password
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

	// Grab keyboard and pointer
	x.GrabKeyboard(display, window, true, x.GrabMode.GrabModeAsync, x.GrabMode.GrabModeAsync, x.CurrentTime)
	x.GrabPointer(display, window, true, x.EventMask{}, x.GrabMode.GrabModeAsync, x.GrabMode.GrabModeAsync, window, 0, x.CurrentTime)

	gc := x.CreateGC(display, window, x.GCAttributeMask{}, nil)
	x.SetForeground(display, gc, white)

	password_buffer: [dynamic]u8
	defer delete(password_buffer)

	running := true
	for running {
		event: x.XEvent
		x.NextEvent(display, &event)

		#partial switch event.type {
		case x.EventType.Expose:
			x.ClearWindow(display, window)
			prompt := "Leave Me Alone. I'm Sleeping "
			x.DrawString(display, window, gc, screen_width / 2 - 100, screen_height / 2, raw_data(prompt), i32(len(prompt)))

			dots := strings.repeat("*", len(password_buffer))
			defer delete(dots)
			x.DrawString(display, window, gc, screen_width / 2 - 50, screen_height / 2 + 30, raw_data(dots), i32(len(dots)))

		case x.EventType.KeyPress:
			key_event := event.xkey
			keysym := x.LookupKeysym(&key_event, 0)

			if keysym == .XK_Return {
				password := string(password_buffer[:])
				// Reject empty passwords
				if len(password) == 0 {
					clear(&password_buffer)
					x.ClearWindow(display, window)
					x.Flush(display)
				} else if verify_password(password) {
					running = false
				} else {
					clear(&password_buffer)
					x.ClearWindow(display, window)
					x.Flush(display)
				}
			} else if keysym == .XK_BackSpace {
				if len(password_buffer) > 0 {
					pop(&password_buffer)
				}
			} else if u32(keysym) >= 0x20 && u32(keysym) <= 0x7E {
				append(&password_buffer, u8(keysym))
			}

			// Redraw
			fake_expose: x.XEvent
			fake_expose.type = x.EventType.Expose
			x.SendEvent(display, window, false, x.EventMask{.Exposure}, &fake_expose)
			x.Flush(display)
		}
	}

	x.UngrabKeyboard(display, x.CurrentTime)
	x.UngrabPointer(display, x.CurrentTime)
	x.FreeGC(display, gc)
	x.DestroyWindow(display, window)
}
