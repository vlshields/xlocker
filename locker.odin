package locker

import "core:fmt"
import "core:os"
import "core:strings"
import "core:c"
import x "vendor:x11/xlib"

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

	correct_password := os.get_env("LOCKER_PASSWORD")
	if correct_password == "" {
		correct_password = "password"
	}

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
				if password == correct_password {
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
